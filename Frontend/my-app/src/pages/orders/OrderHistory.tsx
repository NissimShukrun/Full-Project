import { useEffect } from "react";
import { useAppDispatch, useAppSelector } from "../../store/store";
import { fetchMyOrders, fetchAllOrders } from "../../slices/orderSlice";
import type { Order } from "../../types/types";

const OrderHistory = () => {
  const dispatch = useAppDispatch();
  const { orders, status } = useAppSelector((state) => state.orders);
  const user = useAppSelector((state) => state.auth.user);

  useEffect(() => {
    if (user?.isAdmin === "admin") {
      dispatch(fetchAllOrders());
    } else if (user) {
      dispatch(fetchMyOrders());
    }
  }, [dispatch, user]);

  if (!user) {
    return <p>Please log in to view your orders.</p>;
  }

  return (
    <div className="orders">
      <h2 className="orders-h2">
        {user.isAdmin === "admin" ? "All Orders (Admin):" : "My Orders:"}
      </h2>
      {status === "loading" ? (
        <p>loading orders ...</p>
      ) : orders.length === 0 && status !== "success" ? (
        <p>No orders found.</p>
      ) : (
        <ul>
          {orders.map((order: Order) => (
            <li key={order._id} className="order">
              <strong>Order #{order._id}</strong>
              <br />
              {user.isAdmin === "admin" && order.customer && (
                <>
                  <span>
                    <b>User:</b> {order.customer.name} ({order.customer.email})
                  </span>
                  <br />
                </>
              )}
              <span>
                <b>Total:</b> ${order.totalPrice}
              </span>
              <br />
              <b>Items:</b>
              <ul>
                {order.items &&
                  order.items.map((item, idx) => (
                    <li key={idx} className="order-items">
                      {item.product?.name || "Unknown"} x {item.quantity} - $
                      {item.product?.price || "?"}
                    </li>
                  ))}
              </ul>
              <span>
                <b>Date:</b> {new Date(order.createdAt).toLocaleString()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default OrderHistory;
