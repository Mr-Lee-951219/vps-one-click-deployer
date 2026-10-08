# NodePilot 应用图标

`nodepilot.png` 是高分辨率透明底原图，`nodepilot.ico` 是由原图编码的 Windows 多尺寸图标（16、20、24、32、40、48、64、128、256 像素）。图标用于应用窗口、顶部品牌和打包后的 EXE；原 UI 布局保持。

设计含义：玫红色延续软件强调色，连接的白色节点代表 VPS 与自动配置，向右上方的箭头代表部署和领航。

制作方式：使用内置 imagegen 生成并进行透明边缘修订，随后转换为 Windows ICO；未使用 CLI/API 回退。以下为最终修订提示词：

> Use case: precise-object-edit. Edit this one desktop app icon. Preserve the current bold white connected-node and upward-right arrow symbol, its exact geometry and centered composition. Preserve the rose-red rounded-square tile and its restrained subtle gradient. Change ONLY the contour cleanliness and surrounding transparency: remove every stray red speckle, fringe, texture, residual glow, and pixel outside the tile. The tile must have one absolutely clean smooth rounded-square contour with evenly antialiased edges, like a professionally exported vector app icon. Outside this rounded square everything must be fully transparent alpha=0, especially above and below the tile and at the right edge. Transparent narrow even padding around all sides. Do not add a shadow outside the tile. High resolution square PNG. Do not add any text, letters, new marks, shapes, shadows, decorations or presentation background.
