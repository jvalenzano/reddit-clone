import { mutation, query } from "./_generated/server";
import { getCurrentUserOrThrow } from "./users";
import { v, ConvexError } from "convex/values";
import { getEnrichedPosts } from "./post";

export const create = mutation({
  args: {
    name: v.string(),
    description: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const user = await getCurrentUserOrThrow(ctx);
    const subreddits = await ctx.db.query("subreddit").collect();
    if (subreddits.some((s) => s.name === args.name)) {
      throw new ConvexError({ message: "Subreddit already exists" });
    }
    await ctx.db.insert("subreddit", {
      name: args.name,
      description: args.description,
      authorId: user._id,
    });
  },
});

export const get = query({
  args: { name: v.string() },
  handler: async (ctx, args) => {
    const subreddit = await ctx.db
      .query("subreddit")
      .filter((q) => q.eq(q.field("name"), args.name))
      .unique();
    if (!subreddit) return null;

    const posts = await ctx.db
      .query("post")
      .withIndex("bySubreddit", (q) => q.eq("subreddit", subreddit._id))
      .collect();

    const enrichedPosts = await getEnrichedPosts(ctx, posts);

    return { ...subreddit, posts: enrichedPosts };
  },
});

export const search = query({
  args: { queryStr: v.string() },
  handler: async (ctx, args) => {
    if (!args.queryStr) return [];

    const subreddits = await ctx.db
      .query("subreddit")
      .withSearchIndex("search_body", (q) => q.search("name", args.queryStr))
      .take(10);

    return subreddits.map((sub) => {
      return {...sub, type: "community", title: sub.name}
    })
  },
});
