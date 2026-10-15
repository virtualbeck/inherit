# Simulated account 999999999999; `make demo` renders it.
# Hidden Enters advance demo/bin/inherit, so Sleeps set pacing.
# Sleeps mirror measured real-world timings.
# Theme colors change? Regenerate demo/palette.gif too.

Output docs/demo.gif
Output site/demo.mp4
Output site/demo.webm

Set Shell bash
Set FontSize 14
Set Width 1200
Set Height 960
Set Padding 20
Set TypingSpeed 45ms
Set Theme { "name": "inherit", "background": "#1c1b19", "foreground": "#e8e4dc", "cursor": "#f59e0b", "selection": "#3a3833", "black": "#1c1b19", "red": "#ef4444", "green": "#a3e635", "yellow": "#f59e0b", "blue": "#60a5fa", "magenta": "#c084fc", "cyan": "#22d3ee", "white": "#e8e4dc", "brightBlack": "#9a958c", "brightRed": "#f87171", "brightGreen": "#bef264", "brightYellow": "#fbbf24", "brightBlue": "#93c5fd", "brightMagenta": "#d8b4fe", "brightCyan": "#67e8f9", "brightWhite": "#ffffff" }

Hide
Type "export PATH=$PWD/demo/bin:$PATH PS1='$ ' && clear"
Enter
Show

Sleep 800ms

# scan: ~9s
Type "inherit scan --profile demo"
Sleep 500ms
Enter
# identity + enabled regions
Sleep 1.2s
Enter
Sleep 2s
Type "y"
Sleep 300ms
Enter
# discovery: regions finish over ~5s
Sleep 1s
Enter
Sleep 900ms
Enter
Sleep 800ms
Enter
Sleep 900ms
Enter
Sleep 1.4s
Enter
# hydrate, prune, generate
Sleep 2.6s
Enter
Sleep 3s

# plan: ~14s
Type "inherit plan inherit-999999999999"
Sleep 500ms
Enter
# init downloads the provider
Sleep 6s
Enter
# validate
Sleep 2.5s
Enter
Sleep 1s
Enter
# imports read each resource
Sleep 1.5s
Enter
Sleep 3s
Enter
Sleep 3.5s

# import --fast: ~20s
Type "clear"
Enter
Type "inherit import --fast inherit-999999999999"
Sleep 500ms
Enter
# init, provider cached
Sleep 1.5s
Enter
# validate
Sleep 2.5s
Enter
# plan, verify no-op, apply
Sleep 9s
Enter
Sleep 1s
Enter
# final plan refresh
Sleep 3.5s
Enter
Sleep 4s

# the generated project
Type "clear"
Enter
Type "tree inherit-999999999999"
Sleep 500ms
Enter
Sleep 7s
