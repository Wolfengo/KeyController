-- Package-owned integration with original Hyprland; included from user config.
-- no_anim prevents an outgoing layer snapshot from escaping capture redaction.
hl.layer_rule({
  name = "keycontroller-capture-protection",
  match = { namespace = "^keycontroller-prompt$" },
  no_screen_share = true,
  no_anim = true,
})
