#include <QClipboard>
#include <QContextMenuEvent>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QMimeData>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickWindow>
#include <QSignalSpy>
#include <QTest>
#include <QUrl>

#include <memory>

namespace {
QString fixturePath;

struct ClipboardQueries {
    int formats = 0;
    int hasFormat = 0;
    int data = 0;
    int total() const { return formats + hasFormat + data; }
};

// This is a bounded in-process provider, not the user's platform clipboard.
// Count metadata and payload queries: readOnly must short-circuit before either.
class ObservedMimeData final : public QMimeData {
public:
    explicit ObservedMimeData(std::shared_ptr<ClipboardQueries> queries)
        : queries_(std::move(queries)) {}

    QStringList formats() const override {
        ++queries_->formats;
        return {QStringLiteral("text/plain")};
    }
    bool hasFormat(const QString &mime) const override {
        ++queries_->hasFormat;
        return mime == QStringLiteral("text/plain");
    }

protected:
    QVariant retrieveData(const QString &mime, QMetaType type) const override {
        ++queries_->data;
        if (mime != QStringLiteral("text/plain"))
            return {};
        const QString text = QStringLiteral("synthetic clipboard fixture");
        return type == QMetaType::fromType<QByteArray>() ? QVariant(text.toUtf8()) : QVariant(text);
    }

private:
    std::shared_ptr<ClipboardQueries> queries_;
};

void settle() {
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    QTest::qWait(10);
}
} // namespace

class SearchClipboardTest final : public QObject {
    Q_OBJECT

private slots:
    void readOnlySearchNeverQueriesClipboard() {
        QCOMPARE(QGuiApplication::platformName(), QStringLiteral("offscreen"));
        auto queries = std::make_shared<ClipboardQueries>();
        auto *clipboard = QGuiApplication::clipboard();
        clipboard->setMimeData(new ObservedMimeData(queries));
        settle();
        QCOMPARE(queries->total(), 0);

        QQmlEngine engine;
        const QUrl fixture = QUrl::fromLocalFile(fixturePath);
        engine.addImportPath(fixture.adjusted(QUrl::RemoveFilename).toLocalFile());
        QQmlComponent component(&engine, fixture);
        QVERIFY2(component.isReady(), qPrintable(component.errorString()));
        std::unique_ptr<QObject> object(component.create());
        QVERIFY2(object, qPrintable(component.errorString()));
        auto *root = qobject_cast<QQuickItem *>(object.get());
        QVERIFY(root);
        auto searchItem = [&]() { return root->findChild<QQuickItem *>("bounded-search"); };
        auto *search = searchItem();
        QVERIFY(search);
        QCOMPARE(search->property("readOnly").toBool(), true);
        QCOMPARE(root->property("searchWasWritable").toBool(), false);
        QCOMPARE(queries->total(), 0); // Construction, componentComplete and bindings.

        QQuickWindow window;
        window.resize(480, 160);
        root->setParentItem(window.contentItem());
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        search->forceActiveFocus();
        settle();
        QCOMPARE(queries->total(), 0);
        QSignalSpy writableChanges(search, SIGNAL(readOnlyChanged(bool)));
        QSignalSpy pasteRequests(search, SIGNAL(pasteRequested()));
        QVERIFY(writableChanges.isValid());
        QVERIFY(pasteRequests.isValid());

        // Other applications changing their selection must not make this
        // component ask even for formats, whether it is visible or hidden.
        for (const bool visible : {true, false, true}) {
            search->setVisible(visible);
            clipboard->setMimeData(new ObservedMimeData(queries));
            settle();
            QCOMPARE(search->property("canPaste").toBool(), false);
            QCOMPARE(queries->total(), 0);
        }

        search->forceActiveFocus();
        QTest::keyClick(&window, Qt::Key_A);
        QTest::keyClick(&window, Qt::Key_B);
        settle();
        QCOMPARE(search->property("text").toString(), QStringLiteral("ab"));
        QCOMPARE(queries->total(), 0);

        // Explicit paste keys request the isolated helper; this standalone
        // component must never execute Qt's unbounded native paste operation.
        QTest::keyClick(&window, Qt::Key_V, Qt::ControlModifier);
        QTest::keyClick(&window, Qt::Key_Insert, Qt::ShiftModifier);
        settle();
        QCOMPARE(pasteRequests.count(), 2);
        QCOMPARE(queries->total(), 0);
        QVERIFY(QMetaObject::invokeMethod(search, "paste"));
        settle();
        QCOMPARE(queries->total(), 0);
        QCOMPARE(search->property("text").toString(), QStringLiteral("ab"));

        const QPoint position = search->mapToScene(QPointF(20, 20)).toPoint();
        QTest::mouseClick(&window, Qt::MiddleButton, Qt::NoModifier, position);
        QContextMenuEvent context(QContextMenuEvent::Mouse, QPoint(20, 20),
                                  window.mapToGlobal(position));
        QCoreApplication::sendEvent(search, &context);
        QTest::keyClick(&window, Qt::Key_Menu);
        QTest::keyClick(&window, Qt::Key_Escape);
        settle();
        QCOMPARE(queries->total(), 0);
        QCOMPARE(search->property("readOnly").toBool(), true);
        QCOMPARE(root->property("searchWasWritable").toBool(), false);
        for (const QList<QVariant> &change : writableChanges)
            QCOMPARE(change.at(0).toBool(), true);

        // Destruction removes the native connection entirely. Reopening must
        // not make one initial implicit query against an existing selection.
        QVERIFY(root->setProperty("searchActive", false));
        settle();
        QVERIFY(!searchItem());
        clipboard->setMimeData(new ObservedMimeData(queries));
        settle();
        QCOMPARE(queries->total(), 0);
        QVERIFY(root->setProperty("searchActive", true));
        settle();
        search = searchItem();
        QVERIFY(search);
        QCOMPARE(search->property("readOnly").toBool(), true);
        QCOMPARE(queries->total(), 0);
        QVERIFY(root->setProperty("searchActive", false));
        settle();

        // Positive control: an ordinary editable Qt input in this SAME engine
        // must query the fake provider on dataChanged. Otherwise a zero-query
        // result above would prove only that the harness missed the Qt path.
        QVERIFY(root->setProperty("controlActive", true));
        settle();
        auto *editable = root->findChild<QQuickItem *>("editable-control");
        QVERIFY(editable);
        const int before = queries->total();
        clipboard->setMimeData(new ObservedMimeData(queries));
        settle();
        QVERIFY2(queries->total() > before, "positive control did not observe the native clipboard query");
        QVERIFY(editable->property("canPaste").toBool());
        qInfo("Synthetic clipboard isolation passed on Qt %s; editable-control queries=%d, payload queries=%d",
              qVersion(), queries->total() - before, queries->data);
        root->setParentItem(nullptr);
    }
};

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    fixturePath = QString::fromLocal8Bit(argv[1]);
    // Deliberately override rather than trust the caller's GUI environment.
    // No display service or real clipboard can be reached by this test.
    qputenv("QT_QPA_PLATFORM", "offscreen");
    qputenv("QT_QUICK_BACKEND", "software");
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");
    qunsetenv("WAYLAND_DISPLAY");
    qunsetenv("WAYLAND_SOCKET");
    qunsetenv("DISPLAY");
    int applicationArgc = 1;
    QGuiApplication application(applicationArgc, argv);
    SearchClipboardTest tests;
    return QTest::qExec(&tests, applicationArgc, argv);
}

#include "search-clipboard.moc"
