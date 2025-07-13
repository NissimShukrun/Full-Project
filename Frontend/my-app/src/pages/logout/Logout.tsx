import { useEffect } from "react";
import { useAppDispatch, useAppSelector } from "../../store/store";
import { logoutUser } from "../../slices/authSlice";
import { useNavigate } from "react-router-dom";

const Logout = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const { user } = useAppSelector((state) => state.auth);

  useEffect(() => {
    if (user) {
      const cartKey = `cart_${user._id}`;
      localStorage.removeItem(cartKey);
    }

    dispatch(logoutUser()).then(() => {
      navigate("/login");
    });
  }, [dispatch, navigate, user]);
  return (
    <div>
      <p>Logging out...</p>
    </div>
  );
};

export default Logout;
