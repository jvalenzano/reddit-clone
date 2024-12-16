import { Id } from "../../convex/_generated/dataModel";
import { Link } from "react-router-dom";
import "../styles/Comment.css";

interface CommentProps {
  comment: {
    _id: Id<"comments">;
    content: string;
    author?: {
      username?: string;
    };
    _creationTime: number;
  };
}

const Comment = ({ comment }: CommentProps) => {
  return (
    <div className="comment">
      <div className="comment-header">
        {comment.author?.username ? (
          <Link to={`/u/${comment.author.username}`} className="comment-author">
            u/{comment.author.username}
          </Link>
        ) : (
          <span className="comment-author">deleted</span>
        )}
        <span className="comment-dot">-</span>
        <span className="comment-timestamp">
            {new Date(comment._creationTime).toLocaleString()}
        </span>
      </div>
      <div className="comment-content">{comment.content}</div>
    </div>
  );
};

export default Comment
