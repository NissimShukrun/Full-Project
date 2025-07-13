export interface User {
  name: string;
  email: string;
  password: string;
  isAdmin: string;
  _id: string | number;
}

export interface Product {
  _id: string;
  name: string;
  price: number;
  description: string;
}

export interface CartItem {
  product: Product;
  quantity: number;
}

export interface Order {
  _id: string;
  customer: {
    _id: string;
    name: string;
    email: string;
  };
  items: {
    product: Product;
    quantity: number;
  }[];
  totalPrice: number;
  createdAt: string;
}
