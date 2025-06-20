- the planner agent
for this project the plans most models give without much instructions are already broken, TODO later, focus on the execution part first, as this is most likely to be solved by others soon



- lift to graph
- reduce graph
  by having a graph we can fold some nodes into higher level intent
- transpile to assemblyscript or wasm the nodes, verifying that they "still" work

q: can the transpiling be a finegrained process?
q: what makes the unicorn emu run it so slow? 
  maybe its the tick counter on bios

while vga emulation isn't perfect, we don't need it to be
its good enough to have feedback of what is going on
and we expect to reduce that component to higher level anyways

list components that we need to implement or replace
 bios time counting
 vga memory, graphic registry writing
 don't need mode setting, for a simple poc we know just mode 0x10 -> WM 2

q: what does the minimum case looks like?

q: how pascal strings are rendered?
we can cheat this one with a debug bp, but how would an AI agent actually go about doing it?


