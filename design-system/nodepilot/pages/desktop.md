# NodePilot desktop overrides — v1.3.0

User direction: follow supplied light desktop reference while keeping existing topology.

- Layout unchanged: top brand, centered four tabs, left scrollable config, right persistent live log, fixed deploy footer.
- Background #f3f3f6, white surfaces, text #27272d, secondary #666674, primary #d62f59.
- Rounded cards 18 px, soft shadow blur 20 px alpha 14 offset 4 px; neutral thin borders.
- Primary deploy button uses rose; secondary actions remain neutral.
- Light live log uses monospace text; all dialogs and combo menus explicitly use light palette, including under Windows dark theme.
- Three deployment cards start collapsed, with full-width clickable headers. Certificate choices expand in the card and push later fields down; no floating popup. Ports use numeric QLineEdit fields with a single SVG shuffle button; no spin arrows or random placeholder. Server host/SSH port stay empty even with prior saved configuration.
- Body 14 px, section 17 px, brand 21 px, labels readable at minimum supported size.
- Keep real progress, threaded tasks, accessible keyboard focus, secret masking and protocol safeguards.
- HY2 requires explicit certificate selection/confirmation before deployment; tutorial uses reserved example.com.
