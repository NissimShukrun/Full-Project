import { useAppDispatch, useAppSelector } from "../../store/store";
import { fetchLoginUser, fetchCurrentUser } from "../../slices/authSlice";
import { useState } from "react";

const Login = () => {
  const dispatch = useAppDispatch();
  const { user, message } = useAppSelector((state) => state.auth);

  const [form, setForm] = useState({ email: "", password: "" });
  const [isLogin, setIsLogin] = useState(false);
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await dispatch(
        fetchLoginUser({ email: form.email, password: form.password })
      ).unwrap();
      await dispatch(fetchCurrentUser()).unwrap();
      setIsLogin(true);
    } catch (err) {
      console.error("Login failed", err);
    }
  };

  return (
    <div className="login">
      <h2 className="login-h2">Login</h2>

      {isLogin ? (
        <div className="login-msg">
          {message && <p>{message}</p>}
          {user && <p>{user.name}!</p>}
        </div>
      ) : (
        <form className="login-form" onSubmit={handleSubmit}>
          <div>
            <label>Email:</label>
            <input
              type="email"
              name="email"
              value={form.email}
              onChange={handleChange}
              required
            />
          </div>
          <div>
            <label>Password:</label>
            <input
              name="password"
              type="password"
              value={form.password}
              onChange={handleChange}
              required
            />
          </div>
          <button className="login-btn" type="submit">
            Login
          </button>
        </form>
      )}
    </div>
  );
};

export default Login;
