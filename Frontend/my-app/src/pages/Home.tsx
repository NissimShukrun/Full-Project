import { Link } from "react-router-dom";

const Home = () => {
  return (
    <div className="home">
      <h1 className="home-h1">Welcome to Electronicer</h1>

      <p className="home-p">
        Your one-stop shop for all electronic products and accessories. At
        Electronicer, we provide high-quality gadgets, home appliances, and the
        latest tech at unbeatable prices. Whether you're upgrading your setup or
        looking for a gift, we've got something for everyone.
      </p>

      <p className="home-p">
        Explore a wide range of items – from smartphones and headphones to
        kitchen appliances and smart home devices. Our products are carefully
        selected to ensure you get the best value and performance.
      </p>

      <Link to="/products">
        <button className="home-btn">Browse Products</button>
      </Link>
    </div>
  );
};

export default Home;
