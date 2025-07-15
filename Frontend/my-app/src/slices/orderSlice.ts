import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import type { Order } from "../types/types";
import { logoutUser } from "./authSlice";

interface OrderState {
  orders: Order[];
  status: "idle" | "loading" | "success" | "error" | null;
  error: string | null | undefined;
}

const initialState: OrderState = {
  orders: [],
  status: "idle",
  error: null,
};

export const placeOrder = createAsyncThunk(
  "orders/placeOrder",
  async (items: { product: string; quantity: number }[]) => {
    const response = await fetch("http://localhost:5000/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ items }),
    });
    if (!response.ok) throw new Error("Order failed");
    return response.json();
  }
);

export const fetchMyOrders = createAsyncThunk(
  "orders/fetchMyOrders",
  async () => {
    const response = await fetch("http://localhost:5000/orders", {
      credentials: "include",
    });
    if (!response.ok) throw new Error("Failed to fetch orders");
    return response.json();
  }
);

export const fetchAllOrders = createAsyncThunk(
  "orders/fetchAllOrders",
  async () => {
    const response = await fetch("http://localhost:5000/orders/all", {
      credentials: "include",
    });
    if (!response.ok) throw new Error("Failed to fetch all orders");
    return response.json();
  }
);

const orderSlice = createSlice({
  name: "orders",
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(placeOrder.pending, (state) => {
        state.status = "loading";
      })
      .addCase(placeOrder.fulfilled, (state, action) => {
        state.status = "success";
        state.orders.push(action.payload);
      })
      .addCase(placeOrder.rejected, (state, action) => {
        state.status = "error";
        state.error = action.error.message;
      })
      .addCase(fetchMyOrders.fulfilled, (state, action) => {
        state.orders = action.payload;
        state.status = "idle";
      })
      .addCase(fetchAllOrders.fulfilled, (state, action) => {
        state.orders = action.payload;
        state.status = "idle";
      })
      .addCase(logoutUser.fulfilled, (_state) => {
        return initialState;
      });
  },
});

export default orderSlice.reducer;
