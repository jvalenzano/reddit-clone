import { useQuery } from "convex/react";
import { api } from "../../convex/_generated/api";
import PostCard from "./PostCard";
import "../styles/Feed.css";

export function Feed() {
  const topPosts = useQuery(api.leaderboard.getTopPosts, { limit: 10 });

  if (!topPosts) {
    return <div className="content-grid">Loading...</div>;
  }

  return (
    <div className="content-grid">
      <div className="feed-container">
        <h2 className="section-title">Trending Today</h2>
        <div className="posts-list">
          {topPosts.map((post) => (
            <PostCard key={post._id} post={post} showSubreddit={true} />
          ))}
        </div>
      </div>
    </div>
  );
}
