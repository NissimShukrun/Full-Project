import type { ReactNode } from "react";
import { useAppSelector } from "../store/store";
import { Navigate } from "react-router-dom";

const AdminRoute = ({ children }: { children: ReactNode }) => {
  const { user } = useAppSelector((state) => state.auth);

  if (user && user.isAdmin === "admin") {
    return children;
  }

  return <Navigate to="/login" replace />;
};

export default AdminRoute;
