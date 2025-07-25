// scripts/new-post.ts

import fs from 'fs';
import path from 'path';

const title = process.argv[2];
if (!title) {
  console.error("❌ 请输入文章标题，例如：pnpm run new \"我的新文章\"");
  process.exit(1);
}

const date = new Date().toISOString().split('T')[0];
const slug = title.toLowerCase().replace(/[^a-z0-9]/gi, '-');
const content = `---
title: "${title}"
pubDate: "${date}"
tags: []
description: ""
draft: false
---

开始写作吧...
`;

const filePath = path.resolve(`src/content/posts/${slug}.md`);
fs.writeFileSync(filePath, content, 'utf8');

console.log(`✅ 文章已创建: ${filePath}`);
