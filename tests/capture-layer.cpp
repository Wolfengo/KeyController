#include <QApplication>
#include <QLabel>
#include <QTimer>
#include <QFileInfo>
#include <LayerShellQt/Window>
int main(int argc,char **argv) {
  QApplication app(argc,argv);
  app.setQuitOnLastWindowClosed(false);
  QLabel protectedLayer("SYNTHETIC PRIVATE FIXTURE"), control("PUBLIC CONTROL FIXTURE");
  for (auto *w : {&protectedLayer,&control}) {
    w->setWindowFlags(Qt::FramelessWindowHint);
    w->setFixedSize(220,160);
    w->setAlignment(Qt::AlignCenter);
    w->setStyleSheet(w==&protectedLayer ? "background:#00ff00;color:black;font-size:12px" : "background:#ff00ff;color:black;font-size:12px");
    w->winId();
    auto *layer=LayerShellQt::Window::get(w->windowHandle());
    layer->setScope(w==&protectedLayer ? "keycontroller-prompt" : "keycontroller-capture-control");
    layer->setLayer(LayerShellQt::Window::LayerOverlay);
    layer->setAnchors(w==&protectedLayer ? LayerShellQt::Window::AnchorNone : LayerShellQt::Window::AnchorRight);
    layer->setKeyboardInteractivity(LayerShellQt::Window::KeyboardInteractivityNone);
    layer->setExclusiveZone(-1);
    w->show();
  }
  QTimer closePoll;
  QObject::connect(&closePoll,&QTimer::timeout,[&] { if (QFileInfo::exists(QString::fromLocal8Bit(argv[1]))) protectedLayer.hide(); });
  closePoll.start(20);
  QTimer::singleShot(20000,&app,&QApplication::quit);
  return app.exec();
}
