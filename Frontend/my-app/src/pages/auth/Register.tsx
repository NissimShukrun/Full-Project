import { useAppDispatch, useAppSelector } from "../../store/store";
import { fetchRegisterUser } from "../../slices/authSlice";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

const Register = () => {
  const dispatch = useAppDispatch();
  const { message: registerMessage } = useAppSelector((state) => state.auth);

  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [, setIsRegistered] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    dispatch(
      fetchRegisterUser({
        name: form.name,
        email: form.email,
        password: form.password,
      })
    ).then(() => {
      setIsRegistered(true);
      if (registerMessage) {
        alert(`Registration successful: ${registerMessage}`);
      } else {
        alert("Registration successful!");
      }
      navigate("/login");
    });
  };

  return (
    <div className="register">
      <h2 className="register-h2">Register</h2>

      <form onSubmit={handleSubmit} className="register-form">
        <div>
          <label>Name:</label>
          <input
            type="text"
            name="name"
            value={form.name}
            onChange={handleChange}
            required
          />
        </div>
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
        <button className="register-btn" type="submit">
          Register
        </button>
      </form>
    </div>
  );
};

export default Register;
