# VHS script for assets/demo.gif. See docs/demo-gif.md.
# Run from the repository root after `python examples/create_demo_repo.py`.
Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set TypingSpeed 40ms

Type "athena breaking-changes examples/demo_repo --base v0.1.0 --target v0.2.0 | head -n 40"
Enter
Sleep 8s
