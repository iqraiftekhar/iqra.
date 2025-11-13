import streamlit as st
import pymongo
import bcrypt

# --- MongoDB Connection ---
mongo_uri = st.secrets["mongo"]["uri"]
client = pymongo.MongoClient(mongo_uri)
db = client["ecommerce_db"]
users_col = db["users"]
products_col = db["products"]
orders_col = db["orders"]

# --- Helper Functions ---
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def user_exists(username):
    return users_col.find_one({"username": username}) is not None

def authenticate(username, password):
    user = users_col.find_one({"username": username})
    if user and check_password(password, user["password"]):
        return user
    return None

# --- Admin Panel ---
def admin_panel():
    st.title("🛒 Admin Dashboard")
    st.subheader("Create New User")
    new_username = st.text_input("Username")
    new_password = st.text_input("Password", type="password")
    create_user_btn = st.button("Create User")

    if create_user_btn:
        if user_exists(new_username):
            st.error("User already exists.")
        else:
            users_col.insert_one({
                "username": new_username,
                "password": hash_password(new_password),
                "role": "user"
            })
            st.success(f"User '{new_username}' created successfully!")

    st.subheader("Add Product")
    prod_name = st.text_input("Product Name")
    prod_price = st.number_input("Price", min_value=0.0, step=0.1)
    add_product_btn = st.button("Add Product")

    if add_product_btn:
        if prod_name.strip() == "":
            st.warning("Product name cannot be empty.")
        else:
            products_col.insert_one({
                "name": prod_name,
                "price": prod_price
            })
            st.success(f"Product '{prod_name}' added successfully!")

    st.subheader("Product List")
    products = list(products_col.find())
    for p in products:
        st.write(f"🛍️ {p['name']} - ${p['price']:.2f}")

# --- User Panel ---
def user_panel(username):
    st.title(f"Welcome, {username}!")
    st.subheader("Available Products")

    products = list(products_col.find())
    cart = []

    for product in products:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.write(product['name'])
        with col2:
            st.write(f"${product['price']:.2f}")
        with col3:
            if st.button(f"Add {product['name']} to cart"):
                cart.append(product)

    if len(cart) > 0:
        st.write("🛍️ Items in your cart:")
        total = sum(p['price'] for p in cart)
        for p in cart:
            st.write(f"- {p['name']} (${p['price']:.2f})")
        st.write(f"**Total: ${total:.2f}**")

        if st.button("Buy Now"):
            orders_col.insert_one({
                "username": username,
                "items": [p['name'] for p in cart],
                "total": total
            })
            st.success("✅ Order placed successfully!")

# --- Login Page ---
def login_page():
    st.title("🛍️ Online Store Login")
    role = st.radio("Login as", ["Admin", "User"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = authenticate(username, password)
        if user:
            if role.lower() == user["role"]:
                st.session_state["logged_in"] = True
                st.session_state["role"] = role.lower()
                st.session_state["username"] = username
                st.experimental_rerun()
            else:
                st.error(f"You are not authorized as {role}.")
        else:
            st.error("Invalid username or password.")

# --- Main App Logic ---
def main():
    st.set_page_config(page_title="E-Commerce App", page_icon="🛒")

    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if not st.session_state["logged_in"]:
        login_page()
    else:
        if st.session_state["role"] == "admin":
            admin_panel()
        else:
            user_panel(st.session_state["username"])

        if st.button("Logout"):
            st.session_state.clear()
            st.experimental_rerun()

# --- Initialize Default Admin ---
def ensure_admin_exists():
    admin = users_col.find_one({"username": "admin"})
    if not admin:
        users_col.insert_one({
            "username": "admin",
            "password": hash_password("admin123"),
            "role": "admin"
        })
        print("Default admin created: username='admin', password='admin123'")

if __name__ == "__main__":
    ensure_admin_exists()
    main()
