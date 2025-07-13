import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import "./App.css";
import Header from "./components/Header";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import ProductList from "./pages/products/ProductList";
import ProductDetail from "./pages/products/ProductDetail";
import AdminProductForm from "./pages/products/AdminProductForm";
import Cart from "./pages/cart/Cart";
import Checkout from "./pages/cart/Checkout";
import OrderSuccess from "./pages/cart/OrderSuccess";
import OrderHistory from "./pages/orders/OrderHistory";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import Logout from "./pages/logout/Logout";
import Error from "./components/Error";
import { useEffect } from "react";
import { useAppDispatch } from "./store/store";
import { fetchCurrentUser } from "./slices/authSlice";
import { setCart } from "./slices/cartSlice";
import AdminRoute from "./components/AdminRoute";
import Chatbot from "./components/Chatbot";

function App() {
  const dispatch = useAppDispatch();

  useEffect(() => {
    dispatch(fetchCurrentUser())
      .unwrap()
      .then((user) => {
        if (user && user._id) {
          const cartKey = `cart_${user._id}`;
          const savedCart = localStorage.getItem(cartKey);
          if (savedCart) {
            dispatch(setCart(JSON.parse(savedCart)));
          }
        }
      })
      .catch(() => {});
  }, [dispatch]);
  return (
    <div className="page">
      <Router>
        <Header />

        <Routes>
          <Route path="/" element={<Home />} />

          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          <Route path="/products" element={<ProductList />} />
          <Route path="/products/:id" element={<ProductDetail />} />
          <Route
            path="/admin/products-form"
            element={
              <AdminRoute>
                <AdminProductForm />
              </AdminRoute>
            }
          />
          <Route path="/cart" element={<Cart />} />
          <Route path="/checkout" element={<Checkout />} />
          <Route path="/order-success" element={<OrderSuccess />} />

          <Route path="/orders" element={<OrderHistory />} />

          <Route path="/logout" element={<Logout />} />
          <Route path="*" element={<Error />} />
        </Routes>
        <Chatbot />
        <Footer />
      </Router>
    </div>
  );
}

export default App;
