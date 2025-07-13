import { Link } from "react-router-dom";

const Error = () => {
  return (
    <div>
      <h1 className="title">Page 404 | Page not found</h1>
      <Link to={"/"}>Back to Home page</Link>
    </div>
  );
};

export default Error;
