import { useAppSelector, useAppDispatch } from "../../store/store";
import { removeFromCart, clearCart } from "../../slices/cartSlice";
import { useNavigate } from "react-router-dom";

const Cart = () => {
  const items = useAppSelector((state) => state.cart.items);
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const total = items.reduce(
    (sum, { product, quantity }) => sum + product.price * quantity,
    0
  );

  if (items.length === 0) {
    return (
      <p className="cart-h1" style={{ marginLeft: "20px" }}>
        Your cart is empty.
      </p>
    );
  }

  return (
    <div className="cart">
      <h1 className="cart-h1">Your Cart:</h1>
      <ul className="cart-list">
        {items.map(({ product, quantity }) => (
          <li key={product._id} className="cart-product">
            <div className="cart-div-price">
              <p className="cart-p">
                {product.name} - {quantity} x ${product.price} =
              </p>
              <span className="cart-span">${product.price * quantity}</span>
            </div>
            <button
              className="cart-btn"
              onClick={() => dispatch(removeFromCart(product._id))}
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
      <h2 className="cart-total">
        Total: <span className="cart-total-span">${total}</span>
      </h2>
      <button className="cart-btn-buy" onClick={() => navigate("/checkout")}>
        Buy
      </button>
      <button className="cart-btn-clear" onClick={() => dispatch(clearCart())}>
        Clear Cart
      </button>
    </div>
  );
};

export default Cart;
