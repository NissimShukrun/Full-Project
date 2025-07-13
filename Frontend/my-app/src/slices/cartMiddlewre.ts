import { addToCart, removeFromCart, clearCart } from "../slices/cartSlice";
import { logoutUser } from "../slices/authSlice";

const getCartKey = (userId: any) => `cart_${userId}`;

export const cartMiddleware = (store: any) => (next: any) => (action: any) => {
  const result = next(action);

  const state = store.getState();
  const user = state.auth.user;

  const cartActions = [addToCart.type, removeFromCart.type, clearCart.type];

  if (user && cartActions.includes(action.type)) {
    const cartKey = getCartKey(user._id);
    localStorage.setItem(cartKey, JSON.stringify(state.cart.items));
  }

  if (action.type === logoutUser.fulfilled.type) {
  }

  return result;
};
