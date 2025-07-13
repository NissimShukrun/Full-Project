import { useEffect, useState } from "react";
import { useAppDispatch, useAppSelector } from "../../store/store";
import { fetchProducts } from "../../slices/productSlice";
import { useNavigate } from "react-router-dom";
import { addToCart } from "../../slices/cartSlice";

const ProductList = () => {
  const dispatch = useAppDispatch();
  const products = useAppSelector((state) => state.products.products);
  const [count, setCount] = useState<{ [id: string]: number }>({});
  const navigate = useNavigate();

  useEffect(() => {
    dispatch(fetchProducts());
  }, [dispatch]);

  const handleChangeCount = (id: string, value: string) => {
    setCount((prev) => ({
      ...prev,
      [id]: Number(value),
    }));
  };

  const handleBuy = (id: string) => {
    const product = products.find((p) => p._id === id);
    const quantity = count[id] || 1;
    if (product) {
      dispatch(addToCart({ product, quantity }));
      navigate("/cart");
    }
  };

  const productPage = (id: string) => {
    const product = products.find((p) => p._id === id);
    if (product) {
      navigate(`/products/${id}`);
    }
  };

  return (
    <div className="products">
      <h1 className="products-h1">Products:</h1>

      <ul className="products-list">
        {products.map((p) => (
          <li key={p._id} className="product">
            <p className="products-p">
              {p.name} - <span className="products-span">${p.price}</span>
            </p>
            <div>
              <button
                type="button"
                className="products-btn"
                onClick={() => productPage(p._id)}
              >
                More Details
              </button>
            </div>
            <div>
              <input
                className="products-input"
                type="number"
                name="number"
                min={1}
                placeholder="1"
                onChange={(e) => handleChangeCount(p._id, e.target.value)}
              />
              <button
                type="button"
                className="products-btn"
                onClick={() => handleBuy(p._id)}
              >
                Buy
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default ProductList;
