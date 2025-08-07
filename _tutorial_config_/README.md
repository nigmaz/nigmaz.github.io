# Tutorial Config - nigmaz.github.io

> Step by step build guide for your blog .

- Format to Struct Tree Github : https://gitingest.com/

## A. Step by step Install :

1. Clone repo sử dụng make a copy sau đó git clone về máy để sửa .

```plaintext
Dùng nút “Use this template”
```

2. Cài Nodejs (npm).

```bash
npm -v
```

3. Cài tiếp pnpm từ npm.

```bash
npm install -g pnpm

pnpm -v
```

```bash
pnpm install	# cài dependencies

pnpm dev 		# chạy thử tại http://localhost:4321
```

4. Config 2 File :

- `astro.config.mjs`

```bash
	site: "https://nigmaz.github.io/",
	base: "",
```

- `config.ts` : Thông tin cấu hình hiển thị của Blog Page .

5. Tạo thêm file `"github/workflows/deploy.yml"` để tự động deploy lên github pages .

6. Tạo bài viết mới chạy lệnh sau :

```bash
pnpm new-post <ten-file>
```

```plaintext
Ví dụ : pnpm new-post my-first-post
---
title: My First Blog Post
published: 2023-09-09
description: This is the first post of my new Astro blog.
image: ./cover.jpg
tags: [Foo, Bar]
category: Front-end
draft: false
lang: jp      # Set only if the post's language differs from the site's language in `config.ts`
---
```

## B. Resource References :

- https://docs.astro.build/en/guides/deploy/github

- https://github.com/hkbertoson/github-pages

BLOG Tham khảo :

- https://tvdat20004.github.io

- https://robbert1978.github.io

Mẫu Template :

- https://fuwari.vercel.app

- https://github.com/saicaca/fuwari/tree/main

---

Done!

`">_$ nigmaz"`.
