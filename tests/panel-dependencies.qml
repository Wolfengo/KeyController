import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

ShellRoot {
  id: test
  property var deps: null
  property int calls: 0
  property int installs: 0
  function check(value, message) {
    if (!value) { console.error("DEPENDENCIES_REGRESSION_FAILED", message); Qt.exit(1); throw new Error(message) }
  }
  function find(object, name, seen) {
    if (!object || typeof object !== "object") return null
    seen = seen || []
    if (seen.indexOf(object) >= 0) return null
    seen.push(object)
    if (object.objectName === name) return object
    for (var property of ["data", "children", "contentItem"]) {
      var value = object[property]
      if (!value) continue
      var list = value.length === undefined ? [value] : value
      for (var i = 0; i < list.length; ++i) {
        var result = find(list[i], name, seen)
        if (result) return result
      }
    }
    return null
  }
  function report(state, missing, installable, installing, error) {
    return {schema_version:1, state:state, ui_language:"en", missing:missing || [],
      installable:!!installable, installing:!!installing, error_code:error || null, complete:true,
      setup_required:false, migration_required:false}
  }
  Plugin.Panel {
    id: panel
    manageIpc: false
    checkDependencies: false
    rows: [{key_id:"SHA256:fixture",path:"/fixture/key",name:"Fixture",encrypted:true,state:"locked",bound:false,mode:"password",inherits:true,unavailable:null,unencrypted_copies:[],rules:{lifetime_seconds:0}}]
    function startCall(action, key, value, request) { test.calls++; return true }
    function startDependencyCheck() {
      if (test.deps) test.deps.checking = false
    }
    function startDependencyInstall() { test.installs++ }
  }
  TestCase { id: clock; name: "Dependency UI"; when: false }
  Timer {
    interval: 100; running: true
    onTriggered: {
      test.deps = test.find(panel, "ssh-keys-dependencies")
      test.check(test.deps, "dependency component missing")
      // All package/terminal/API operations are intercepted; never touch the
      // real pacman database, installed packages, system service or keys.
      panel.checkDependencies = true
      var packages = [
        {name:"qt6-svg",requirement:"qt6-svg",repository:"extra",available:true,reason:null},
        {name:"layer-shell-qt",requirement:"layer-shell-qt>=6.6",repository:"extra",available:true,reason:null}
      ]
      test.deps.accept(test.report("missing", packages, true))
      panel.open()
      clock.wait(100)
      var button = test.find(panel, "ssh-keys-install-dependencies")
      var row = test.find(panel, "ssh-key-access")
      test.check(button.visible && button.enabled && !row.visible, "missing dependencies did not replace controls")
      test.check(button.text === "Install and set up", "combined action does not disclose setup")
      test.check(test.find(panel, "ssh-keys-setup-scope").visible, "setup scope is hidden before consent")
      test.check(test.deps.wizardCommand().slice(-1)[0] === "--wizard", "button still launches separate install/setup")
      test.check(!panel.call("keys.unlock", "SHA256:fixture") && test.calls === 0, "missing dependencies allowed key API")
      button.clicked()
      button.clicked()
      test.check(test.installs === 1 && !button.enabled, "duplicate terminal launch")
      test.deps.accept(test.report("missing", packages, true, true))
      test.check(!button.enabled && button.busy, "installer state not shown")
      test.deps.accept(test.report("ready", [], false, true))
      test.check(!panel.dependenciesReady && !row.visible, "in-progress wizard exposed key controls")
      test.deps.accept(test.report("ready"))
      clock.wait(100)
      test.check(panel.dependenciesReady && row.visible && !button.visible, "ready did not restore existing controls")
      test.check(test.calls > 0, "ready did not refresh metadata")
      var originalRow = row
      test.deps.accept(test.report("ready"))
      clock.wait(50)
      test.check(test.find(panel, "ssh-key-access") === originalRow, "recheck recreated a key control")
      var initial = test.report("ready")
      initial.setup_required = true
      test.deps.accept(initial)
      test.check(!panel.dependenciesReady && button.enabled && button.text === "Set up KeyController", "first installation lost setup guidance")
      var migration = test.report("ready")
      migration.migration_required = true
      test.deps.accept(migration)
      test.check(!panel.dependenciesReady && button.enabled, "unfinished migration was considered ready")
      test.deps.fail("invalid_response")
      test.check(!button.enabled, "failed setup check left setup action enabled")
      test.deps.accept(test.report("missing", [{name:"keycontroller",requirement:"keycontroller>=0.1.0-24",repository:null,available:false,reason:"repository_unavailable"}], false))
      test.check(!button.enabled && !row.visible, "unavailable helper offered installation")
      test.check(button.text === "Package not yet available", "unavailable helper has misleading install action")
      var packageStatus = test.find(panel, "ssh-keys-package-status")
      test.check(packageStatus.visible && test.deps.packageStatusUrl === "https://github.com/omacom/omarchy-pkgs/pull/857", "package publication status is missing")
      test.deps.accept(test.report("error", [], false, false, "package_check_failed"))
      test.check(!panel.dependenciesReady && !button.enabled, "check failure allowed key access")
      test.check(!packageStatus.visible, "stale publication link shown for unrelated errors")
      test.deps.accept(test.report("error", [], false, false, "unsupported_repositories"))
      test.check(!button.enabled && test.find(panel, "ssh-keys-dependencies-message").text.indexOf("Other repositories were detected") >= 0, "custom repositories did not explain why installation is blocked")
      test.deps.accept(test.report("ready"))
      var malformed = test.report("ready")
      malformed.setup_required = "false"
      var rejected = false
      try { test.deps.accept(malformed) }
      catch (error) { rejected = true; test.deps.fail("invalid_response") }
      test.check(rejected && !panel.dependenciesReady, "malformed setup state allowed key access")
      panel.uiLanguage = "ru"
      test.check(button.text === "Установить и настроить", "Russian combined label missing")
      panel.close()
      console.log("KEYCONTROLLER_DEPENDENCIES_REGRESSION_OK")
      Qt.quit()
    }
  }
}
