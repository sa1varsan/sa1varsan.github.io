// @ts-check

import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';
import rehypeKatex from 'rehype-katex';
import remarkMath from 'remark-math';

const owner = process.env.GITHUB_REPOSITORY_OWNER;
const repository = process.env.GITHUB_REPOSITORY?.split('/')[1];
const site = process.env.SITE_URL ?? (owner ? `https://${owner}.github.io` : 'https://example.github.io');
const base = repository && owner && repository !== `${owner}.github.io` ? `/${repository}` : undefined;
const remarkPlugins = [remarkMath];
const rehypePlugins = [rehypeKatex];

// https://astro.build/config
export default defineConfig({
	site,
	base,
	markdown: {
		remarkPlugins,
		rehypePlugins,
	},
	integrations: [
		mdx({
			remarkPlugins,
			rehypePlugins,
		}),
		sitemap(),
	],
});
