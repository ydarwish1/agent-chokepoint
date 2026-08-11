# The taint recording, as a re-runnable recipe.
#
#     vhs docs/demo/tainted-run.tape      # from the repo root
#
# It drives a real terminal running the real demo against the committed policy;
# nothing here edits what the demo prints. The GIF is a measurement in the same
# sense telemetry/dashboard.png is: it is replaced by a newer run, never
# retouched. Re-record it whenever the demo's output changes.
#
# The Hide block is the venv activation and a clear. It is hidden because it is
# not the subject, not because it is doing anything: it is written out here in
# the committed recipe so a reader can see exactly what was off-camera.
#
# Dimensions are sized so the whole transcript fits without scrolling — a reader
# who pauses on any frame can see the leg above the one being drawn. The check is
# the recording itself: extract the last frame and look for the command line at
# the top of it. Re-run that check whenever the demo grows a line.

Output docs/demo/tainted-run.gif

Set Shell "bash"
Set FontSize 13
Set Width 980
Set Height 1030
Set Padding 20
Set Framerate 10
Set TypingSpeed 45ms

Hide
Type "source .venv/bin/activate && clear"
Enter
Sleep 2s
Show

Sleep 1s
Type "python proxy/demo/tainted_run.py"
Sleep 800ms
Enter
Sleep 20s
