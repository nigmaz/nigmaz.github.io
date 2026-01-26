# Tutorial Config - nigmaz.github.io

> Step by step build guide for your blog .

- Format to Struct Tree Github : https://gitingest.com/

## A. Step by step Install :

1. Clone repo sử dụng make a copy sau đó git clone về máy để sửa .

```plaintext
Dùng nút "Use this template"
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

## B. Note Config :

[+] Image: Pixel art hoặc Mosaic art .

[+] `astro.config.mjs` : cấu hình cho trang web .

[+] `config.ts` : Thông tin cấu hình hiển thị của Blog Page .

[+] `Layout.astro` : Cấu trúc layout cho trang blog .

- "src/constants/constants.ts" là file chưa giá trị define cho theme mặc định khi vào Blog .

- "D:\_GITHUB\nigmaz.github.io\public\favicon" .

- Chỉnh sửa file "config.ts" đoạn này để chỉnh hiển thị ảnh banner vào chính giữa hay lên trên.

```ts
export const siteConfig: SiteConfig = {
	title: "nigmaz",
	subtitle: "Blog [ >_$ ]",
	lang: "en", // Language code, e.g. 'en', 'zh-CN', 'ja', etc.
	themeColor: {
		hue: 145, // Default hue for the theme color, from 0 to 360. e.g. red: 0, teal: 200, cyan: 250, pink: 345
		fixed: true, // Hide the theme color picker for visitors
	},
	banner: {
		enable: true,
		// src: "assets/images/demo-banner.png", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
		src: "assets/images/banner.png",
		// position: "center", // Equivalent to object-position, only supports 'top', 'center', 'bottom'. 'center' by default
		position: "bottom",
		credit: {
			enable: false, // Display the credit text of the banner image
			text: "", // Credit text to be displayed
			url: "", // (Optional) URL link to the original artwork or artist's page
		},
	},
	toc: {
		enable: true, // Display the table of contents on the right side of the post
		depth: 2, // Maximum heading depth to show in the table, from 1 to 3
	},
	favicon: [
		// Leave this array empty to use the default favicon
		// {
		//   src: '/favicon/icon.png',    // Path of the favicon, relative to the /public directory
		//   theme: 'light',              // (Optional) Either 'light' or 'dark', set only if you have different favicons for light and dark mode
		//   sizes: '32x32',              // (Optional) Size of the favicon, set only if you have favicons of different sizes
		// }
	],
};
```

- Chỉnh sửa file "Layout.astro" đoạn này để chỉnh hiển thị ảnh banner vào chính giữa hay lên trên.

```css
@tailwind components;
@layer components {
	.enable-banner.is-home #banner-wrapper {
		@apply h-[var(--banner-height-home)] translate-y-[var(--banner-height-extend)]
	}
	.enable-banner #banner-wrapper {
		@apply h-[var(--banner-height-home)]
	}

	.enable-banner.is-home #banner {
		@apply h-[var(--banner-height-home)] translate-y-0
	}
	.enable-banner #banner {
		@apply h-[var(--banner-height-home)] translate-y-[var(--bannerOffset)]
	}
	.enable-banner.is-home #main-grid {
		/* @apply translate-y-[var(--banner-height-extend)]; */
		@apply translate-y-0;
	}
	.enable-banner #top-row {
		@apply h-[calc(var(--banner-height-home)_-_4.5rem)] transition-all duration-300
	}
	.enable-banner.is-home #sidebar-sticky {
		@apply top-[calc(1rem_-_var(--banner-height-extend))]
	}
	.navbar-hidden {
		@apply opacity-0 -translate-y-16
	}
}
</style>
```   

- Thêm vào "astro.config.mjs" để không thực hiện build các file trong black-list 

```mjs
export default defineConfig({
  // ...
-  vite: {
-    build: {
-      rollupOptions: {
-        onwarn(warning, warn) {
-          if (
-            warning.message.includes("is dynamically imported by") &&
-            warning.message.includes("but also statically imported by")
-          ) {
-            return;
-          }
-          warn(warning);
-        },
-      },
-    },
-  },
+  vite: {
+    assetsInclude: [
+      '**/*.py',
+      '**/*.zip',
+      '**/*.7z',
+      '**/*.xz',
+      '**/*.bin',
+      '**/*.dmp',
+      '**/*.hex'
+    ],
+    build: {
+      rollupOptions: {
+        onwarn(warning, warn) {
+          if (
+            warning.message.includes("is dynamically imported by") &&
+            warning.message.includes("but also statically imported by")
+          ) {
+            return;
+          }
+          warn(warning);
+        },
+      },
+    },
+  },
});
```

## C. Resource References :

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
