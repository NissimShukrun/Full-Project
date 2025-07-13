import { useEffect, useState } from "react";
import { useAppDispatch, useAppSelector } from "../../store/store";
import {
  fetchProducts,
  fetchUpdateProduct,
  fetchDeleteProduct,
  fetchCreateProduct,
} from "../../slices/productSlice";
import type { Product } from "../../types/types";

type FormState = {
  _id: string | null;
  name: string;
  price: string;
  description: string;
};

const initialFormState: FormState = {
  _id: null,
  name: "",
  price: "",
  description: "",
};

const AdminProductForm = () => {
  const dispatch = useAppDispatch();
  const products = useAppSelector((state) => state.products.products);

  const [formData, setFormData] = useState(initialFormState);

  useEffect(() => {
    dispatch(fetchProducts());
  }, [dispatch]);

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const clearForm = () => {
    setFormData(initialFormState);
  };

  const handleEdit = (product: Product) => {
    setFormData({
      _id: product._id,
      name: product.name,
      price: String(product.price),
      description: product.description,
    });
    window.scrollTo(0, 0);
  };

  const handleDelete = (id: string) => {
    if (window.confirm("Are you sure you want to delete this product?")) {
      dispatch(fetchDeleteProduct(id));
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const productData = {
      name: formData.name,
      price: Number(formData.price),
      description: formData.description,
    };

    if (formData._id) {
      dispatch(fetchUpdateProduct({ id: formData._id, ...productData }));
    } else {
      dispatch(fetchCreateProduct(productData));
    }
    clearForm();
  };

  return (
    <div className="admin-products-changes">
      <div>
        <h2 className="admin-h2">
          {formData._id ? "Edit Product:" : "Add a New Product:"}
        </h2>

        <form onSubmit={handleSubmit} className="admin-form">
          <label>Product Name:</label>
          <input
            type="text"
            name="name"
            placeholder="Product Name"
            value={formData.name}
            onChange={handleInputChange}
            required
          />
          <label>Price:</label>
          <input
            type="number"
            name="price"
            placeholder="Price"
            value={formData.price}
            onChange={handleInputChange}
            required
          />
          <label>Description:</label>
          <textarea
            name="description"
            value={formData.description}
            onChange={handleInputChange}
            required
          ></textarea>
          <button type="submit" className="admin-btn-form">
            {formData._id ? "Update Product" : "Add Product"}
          </button>
          {formData._id && (
            <button
              type="submit"
              className="admin-btn-form"
              onClick={clearForm}
            >
              Cancel Edit
            </button>
          )}
        </form>
      </div>

      <h2 className="admin-h2">Exsiting Products:</h2>
      <ul className="admin-products-list">
        {products.map((p) => (
          <li key={p._id} className="admin-product">
            <h4>
              {p.name} - ${p.price}
            </h4>
            <p className="admin-p">{p.description}</p>
            <div>
              <button
                type="button"
                className="admin-btn"
                onClick={() => handleEdit(p)}
              >
                Edit ✏️
              </button>
              <button
                type="button"
                className="admin-btn"
                onClick={() => handleDelete(p._id)}
              >
                Delete 🗑️
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default AdminProductForm;
