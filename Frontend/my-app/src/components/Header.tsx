import { Link } from "react-router-dom";
import { useAppSelector } from "../store/store";
import { RxHamburgerMenu } from "react-icons/rx";
import { useState } from "react";

const Header = () => {
  const user = useAppSelector((state) => state.auth.user);
  const [menuOpen, setMenuOpen] = useState(false);

  const toggleMenu = () => setMenuOpen((prev) => !prev);

  return (
    <div>
      <nav className="header-navbar">
        {user && <span className="hello-nav">Hello, {user.name}</span>}

        <button className="hamburger-btn" onClick={toggleMenu}>
          <RxHamburgerMenu size={24} />
        </button>

        <div className="nav-links">
          <Link to="/" className="links">
            Home
          </Link>
          <Link to="/products" className="links">
            Products
          </Link>
          <Link to="/cart" className="links">
            Cart
          </Link>
          {!user && (
            <>
              <Link to="/register" className="links">
                Register
              </Link>
              <Link to="/login" className="links">
                Login
              </Link>
            </>
          )}
          {user && (
            <>
              <Link to="/orders" className="links">
                My Orders
              </Link>
              <Link to="/logout" className="links">
                Logout
              </Link>
            </>
          )}
          {user?.isAdmin === "admin" && (
            <Link to="/admin/products-form" className="links">
              Products Changes
            </Link>
          )}
        </div>

        {menuOpen && (
          <div className="mobile-menu">
            <Link to="/" className="links" onClick={toggleMenu}>
              Home
            </Link>
            <Link to="/products" className="links" onClick={toggleMenu}>
              Products
            </Link>
            <Link to="/cart" className="links" onClick={toggleMenu}>
              Cart
            </Link>
            {!user && (
              <>
                <Link to="/register" className="links" onClick={toggleMenu}>
                  Register
                </Link>
                <Link to="/login" className="links" onClick={toggleMenu}>
                  Login
                </Link>
              </>
            )}
            {user && (
              <>
                <Link to="/orders" className="links" onClick={toggleMenu}>
                  My Orders
                </Link>
                <Link to="/logout" className="links" onClick={toggleMenu}>
                  Logout
                </Link>
              </>
            )}
            {user?.isAdmin === "admin" && (
              <Link
                to="/admin/products-form"
                className="links"
                onClick={toggleMenu}
              >
                Products Changes
              </Link>
            )}
          </div>
        )}
      </nav>
    </div>
  );
};

export default Header;
