import { useState } from "react";
import { useAppDispatch, useAppSelector } from "../../store/store";
import { placeOrder } from "../../slices/orderSlice";
import { clearCart } from "../../slices/cartSlice";
import { useNavigate } from "react-router-dom";

const Checkout = () => {
  const items = useAppSelector((state) => state.cart.items);
  const orderStatus = useAppSelector((state) => state.orders.status);
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const [form, setForm] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    address: "",
    city: "",
    country: "",
    zip: "",
    cardName: "",
    cardNumber: "",
    expiry: "",
    cvv: "",
  });

  const [errors, setErrors] = useState<{ [key: string]: string }>({});

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setForm({ ...form, [name]: value });
  };

  const validate = () => {
    const newErrors: { [key: string]: string } = {};

    if (!form.firstName) newErrors.firstName = "First name is required";
    if (!form.lastName) newErrors.lastName = "Last name is required";
    if (!/\S+@\S+\.\S+/.test(form.email)) newErrors.email = "Invalid email";
    if (!/^\d{10,15}$/.test(form.phone))
      newErrors.phone = "Phone must be numbers only (10-15 digits)";
    if (!form.address) newErrors.address = "Address is required";
    if (!form.city) newErrors.city = "City is required";
    if (!form.country) newErrors.country = "Country is required";
    if (!form.zip) newErrors.zip = "ZIP code is required";

    if (!form.cardName) newErrors.cardName = "Cardholder name is required";
    if (!/^\d{16}$/.test(form.cardNumber))
      newErrors.cardNumber = "Card number must be 16 digits";
    if (!/^(0[1-9]|1[0-2])\/\d{2}$/.test(form.expiry))
      newErrors.expiry = "Expiry must be in MM/YY format";
    if (!/^\d{3,4}$/.test(form.cvv))
      newErrors.cvv = "CVV must be 3 or 4 digits";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (validate()) {
      const orderItems = items.map(({ product, quantity }) => ({
        product: product._id,
        quantity,
      }));
      try {
        await dispatch(placeOrder(orderItems)).unwrap();
        dispatch(clearCart());
        navigate("/order-success");
      } catch (err) {
        console.error("Failed to plade order:", err);
        alert("There was a problem placing your order. Please try again.");
      }
    }
  };
  return (
    <div className="checkout">
      <h2 className="checkout-h2">Checkout</h2>
      <form onSubmit={handleSubmit}>
        <h3 className="checkout-h3">Personal Information</h3>
        <input
          name="firstName"
          placeholder="First Name"
          value={form.firstName}
          onChange={handleChange}
        />
        <div>{errors.firstName}</div>

        <input
          name="lastName"
          placeholder="Last Name"
          value={form.lastName}
          onChange={handleChange}
        />
        <div>{errors.lastName}</div>

        <input
          name="email"
          placeholder="Email"
          value={form.email}
          onChange={handleChange}
        />
        <div>{errors.email}</div>

        <input
          name="phone"
          placeholder="Phone Number"
          value={form.phone}
          onChange={handleChange}
        />
        <div>{errors.phone}</div>

        <h3 className="checkout-h3">Address</h3>
        <input
          name="address"
          placeholder="Street Address"
          value={form.address}
          onChange={handleChange}
        />
        <div>{errors.address}</div>

        <input
          name="city"
          placeholder="City"
          value={form.city}
          onChange={handleChange}
        />
        <div>{errors.city}</div>

        <input
          name="country"
          placeholder="Country"
          value={form.country}
          onChange={handleChange}
        />
        <div>{errors.country}</div>

        <input
          name="zip"
          placeholder="ZIP / Postal Code"
          value={form.zip}
          onChange={handleChange}
        />
        <div>{errors.zip}</div>

        <h3 className="checkout-h3">Payment</h3>
        <input
          name="cardName"
          placeholder="Cardholder Name"
          value={form.cardName}
          onChange={handleChange}
        />
        <div>{errors.cardName}</div>

        <input
          name="cardNumber"
          placeholder="Card Number"
          value={form.cardNumber}
          onChange={handleChange}
        />
        <div>{errors.cardNumber}</div>

        <input
          name="expiry"
          placeholder="MM/YY"
          value={form.expiry}
          onChange={handleChange}
        />
        <div>{errors.expiry}</div>

        <input
          name="cvv"
          placeholder="CVV"
          value={form.cvv}
          onChange={handleChange}
        />
        <div>{errors.cvv}</div>
        <button
          className="checkout-btn"
          type="submit"
          disabled={orderStatus === "loading"}
        >
          {orderStatus === "loading" ? "Processing..." : "Pay Now"}
        </button>
      </form>
    </div>
  );
};

export default Checkout;
