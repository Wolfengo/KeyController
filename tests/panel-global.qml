import QtQuick
import Quickshell
import QtTest
import "plugin" as Plugin

ShellRoot {
  id: test
  property var rpc: null
  property int opens: 0
  property int statuses: 0
  property string outcome: "completed"
  property string requestId: "native-policy-1"
  property var saved: ({lifetime_seconds:60,revoke_on_sleep:true})
  property var proposed: ({lifetime_seconds:900,revoke_on_sleep:false})
  property double expiry: Math.floor(Date.now()/1000)+50
  function check(value, message) {
    if (!value) {console.error("GLOBAL_SETTINGS_REGRESSION_FAILED",message);Qt.exit(1);throw new Error(message)}
  }
  function find(object,name,seen) {
    if(!object || typeof object !== "object") return null
    seen=seen || [];if(seen.indexOf(object)>=0)return null;seen.push(object)
    if(object.objectName===name)return object
    for(var prop of ["data","children","contentItem"]){
      var value=object[prop];if(!value)continue
      var list=value.length===undefined?[value]:value
      for(var i=0;i<list.length;++i){var found=find(list[i],name,seen);if(found)return found}
    }
    return null
  }
  function idle(){return !rpc.running&&!panel.rpcInFlight&&!panel.queuedCall&&!panel.submittingAction&&!panel.deferredAction}
  function waitFor(fn,message){var until=Date.now()+2500;while(!fn()&&Date.now()<until)clock.wait(15);check(fn(),message)}
  Plugin.Panel {
    id:panel
    uiLanguage:"en"
    manageIpc:false
    function refresh(){}
    function startCall(action,key,value,request){
      var result={api_version:1,state:"ready",error_code:null,request_id:null,key_id:null}
      if(action==="settings.global"){
        test.opens++
        test.check(key===null&&value===null,"widget supplied policy or consent")
        result.state="pending";result.request_id=test.requestId;result.operation="settings.global"
      }else if(action==="requests.status"){
        test.statuses++
        test.check(request===test.requestId,"wrong editor request")
        result.state=test.outcome;result.operation="settings.global";result.request_id=request
        if(test.outcome==="completed"||test.outcome==="partial")test.saved=test.proposed
        if(test.outcome==="partial")result.error_code="settings_durability_unknown"
      }else if(action==="panel.list"){
        result.ui_language="en";result.global_rules=test.saved
        result.scanned=true;result.scan_root="/test/.ssh";result.scan_requires_consent=false;result.active_request=null
        result.keys=[{key_id:"SHA256:fixture",name:"Fixture",path:"/test/.ssh/fixture",fingerprint:"SHA256:fixture",
          encrypted:true,unavailable:null,unencrypted_copies:[],state:"unlocked",expires_at:test.expiry,lifetime_known:true,
          bound:true,mode:"fingerprint",inherits:true,rules:{lifetime_seconds:test.saved.lifetime_seconds}}]
      }else test.check(false,"unexpected or unprotected action: "+action)
      test.rpc.command=["/usr/bin/python3",Quickshell.env("SSH_KEYS_TEST_REPLY"),JSON.stringify(result),"0.15"]
      test.rpc.running=true
      return true
    }
  }
  TestCase{id:clock;when:false}
  Timer{
    interval:100;running:true
    onTriggered:{
      test.rpc=test.find(panel,"ssh-keys-rpc")
      test.check(test.rpc,"RPC missing")
      panel.open()
      test.check(!panel.editRules(null),"unknown policy was editable")
      panel.call("panel.list");test.waitFor(test.idle,"initial metadata failed")
      var repeater=test.find(panel,"ssh-key-rows")
      var originalRow=repeater.itemAt(0)
      panel.settingsFor(panel.rows[0])
      for(var resultState of ["completed","cancelled","partial"]){
        test.outcome=resultState;test.requestId="native-"+resultState
        test.proposed={lifetime_seconds:resultState==="completed"?900:1800,revoke_on_sleep:resultState!=="completed"}
        panel.open()
        var previous=JSON.stringify(panel.globalRules)
        var before=test.opens
        test.check(panel.editRules(null),"editor launch failed")
        test.check(!panel.editRules(null),"duplicate click accepted")
        test.check(JSON.stringify(panel.globalRules)===previous,"launch optimistically changed rules")
        test.waitFor(function(){return test.idle()&&panel.activeRequest===test.requestId},"pending editor not tracked")
        test.check(!panel.opened,"widget overlays native editor")
        test.check(test.opens===before+1,"more than one window requested")
        panel.call("requests.status",null,null,test.requestId)
        test.waitFor(function(){return test.idle()&&!panel.activeRequest},"editor completion not reconciled")
        test.check(JSON.stringify(panel.globalRules)===JSON.stringify(test.saved),"authoritative rules not refreshed")
        test.check(panel.settingsRow.rules.lifetime_seconds===test.saved.lifetime_seconds,
          "open key details retained old inherited policy")
        if(resultState==="cancelled")test.check(JSON.stringify(panel.globalRules)===previous,"cancelled editor changed policy")
        if(resultState==="partial")test.check(panel.message===panel.describe("settings_durability_unknown"),"partial save hidden")
        test.check(panel.rows[0].expires_at===test.expiry&&panel.rows[0].state==="unlocked"&&panel.rows[0].mode==="fingerprint",
          "policy refresh changed loaded access")
        test.check(repeater.itemAt(0)===originalRow,"metadata recreated key row")
      }
      panel.close();console.log("SSH_KEYS_GLOBAL_SETTINGS_REGRESSION_OK");Qt.quit()
    }
  }
}
