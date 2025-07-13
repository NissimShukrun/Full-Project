import { Link } from "react-router-dom";

const OrderSuccess = () => {
  return (
    <div style={{ textAlign: "center", padding: "50px" }}>
      <h1>Order Successfully ✔</h1>
      <p>Thank you for your purchase.</p>
      <p>
        Your order is being processed, an order confirmation will be sent to you
        by email.
      </p>
      <Link
        to="/orders"
        style={{
          display: "inline-block",
          marginTop: "20px",
          padding: "10px 20px",
          backgroundColor: "#007bff",
          color: "white",
          textDecoration: "none",
          borderRadius: "5px",
        }}
      >
        View your orders
      </Link>
      <br />
      <Link
        to="/products"
        style={{
          display: "inline-block",
          marginTop: "10px",
          color: "#007bff",
        }}
      >
        Continue shopping
      </Link>
    </div>
  );
};

export default OrderSuccess;
