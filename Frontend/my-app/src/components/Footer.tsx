const Footer = () => {
  return (
    <div className="footer">
      <h3 className="footer-h3">Contact Us</h3>
      <ul className="footer-lists">
        <li className="footer-li">Company: electronicer</li>
        <li className="footer-li">Email: electronicer12@gmail.com</li>
        <li className="footer-li">Phone: +1-234-567-8901</li>
        <li className="footer-li">Address: NW West born 78</li>
      </ul>
      <p className="footer-li">
        {" "}
        © {new Date().getFullYear()} electronicer. All rights reserved.
      </p>
    </div>
  );
};

export default Footer;
