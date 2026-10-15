# Demo GIF for README.md. Render with `make demo` (needs VHS and the
# blackwall-stack Docker lab: tests/bin/bw-lab up).

Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 720
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set Framerate 15
Set PlaybackSpeed 1.0

# Use the freshly built binary and the lab-only config.
Hide
Type "export PATH=$PWD/bin:$PATH BW_CONFIG=docs/demo-config.yaml PS1='$ ' && clear"
Enter
Sleep 500ms
Show

Type "blackwall --context lab"
Sleep 300ms
Enter
Sleep 3s

# Agents table -> drill into black-host-01: Overview, Top.
Down
Sleep 700ms
Enter
Sleep 2.5s
Type "t"
Sleep 2.5s
Escape
Sleep 1s

# Live alerts feed, open one alert card.
Type ":alerts"
Sleep 400ms
Enter
Sleep 3s
Down
Sleep 400ms
Down
Sleep 400ms
Enter
Sleep 3s
Escape
Sleep 1s

# Back to the agent, Sessions tab.
Type ":agents"
Sleep 400ms
Enter
Sleep 1.5s
Enter
Sleep 1s
Type "e"
Sleep 3.5s

Type "q"
Sleep 1s
