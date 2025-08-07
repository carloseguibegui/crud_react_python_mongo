# Proyecto Full-Stack con React y FastAPI

## **Front-End: React**

React es una biblioteca de JavaScript para construir interfaces de usuario. A diferencia de Angular, que es un framework completo, React se centra únicamente en la capa de vista (View) en el patrón MVC. Esto significa que React es más flexible y requiere que los desarrolladores elijan otras herramientas para manejar aspectos como el enrutamiento o la gestión del estado global.

### **Fundamentos de React**

#### **Componentes**
- **Qué son**: Los componentes son bloques de construcción reutilizables que definen cómo se ve y se comporta una parte de la interfaz de usuario.
- **Tipos**:
  - **Componentes funcionales**: Son funciones de JavaScript que retornan JSX. Son más simples y se usan ampliamente en React moderno.
  - **Componentes de clase**: Son clases de ES6 que extienden `React.Component`. Aunque siguen siendo válidos, se usan menos desde la introducción de los hooks.

#### **JSX (JavaScript XML)**
- **Qué es**: Una extensión de sintaxis que permite escribir HTML dentro de JavaScript. JSX se transpila a llamadas de funciones de React como `React.createElement`.

#### **Estado y Props**
- **Props**: Datos que se pasan de un componente padre a un componente hijo. Son inmutables dentro del componente hijo.
- **Estado**: Es un objeto que pertenece a un componente y puede cambiar con el tiempo. En componentes funcionales, se maneja con el hook `useState`.

#### **Hooks**
- **useState**: Permite agregar estado local a un componente funcional.
- **useEffect**: Maneja efectos secundarios como llamadas a APIs, suscripciones o manipulación del DOM.
- **useContext**: Permite acceder a un contexto sin necesidad de pasar props manualmente a través de cada nivel del árbol de componentes.

#### **Gestión del estado global**
- **Redux**: Se utiliza para manejar el estado global en aplicaciones grandes. Proporciona un `store` centralizado, acciones y reducers para manejar el estado.
- **Context API**: Útil para evitar el "prop drilling" y compartir estado entre componentes relacionados.

#### **Enrutamiento**
- React Router se utiliza para manejar la navegación entre páginas. Proporciona componentes como `BrowserRouter`, `Routes` y `Route` para definir rutas y redirecciones.

---


## **Back-End: FastAPI**

FastAPI es un framework moderno y de alto rendimiento para construir APIs con Python. En este proyecto, se utiliza junto con MongoDB para gestionar usuarios, autenticación y un inventario multiusuario. A continuación se muestra el código clave y su explicación:

### **main.py (FastAPI + MongoDB + JWT)**

```python
from fastapi import FastAPI, UploadFile, Form, HTTPException, Depends
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from bson import ObjectId
from passlib.context import CryptContext

# Cargar variables de entorno
load_dotenv()
MONGO_URL = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URL)
db  = client.test_database

app = FastAPI()

# Middleware CORS
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo de inventario
class InventoryItem(BaseModel):
    name: str
    quantity: int
    description: str
    user_id: str
    id: str | None = None

# Configuración de JWT y bcrypt
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Obtener usuario autenticado
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Endpoint de autenticación
@app.post("/api/v1/auth/login")
async def login(username: str = Form(...), password: str = Form(...)) -> Dict[str, str]:
    user = await db.user.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Credenciales inválidas")
    expiration = datetime.now(timezone.utc) + timedelta(hours=1)
    token = jwt.encode({"sub": str(user["_id"]), "exp": expiration}, SECRET_KEY, algorithm=ALGORITHM)
    return {"message": "Inicio de sesión exitoso", "token": token}

# Endpoint de registro
@app.post("/api/v1/auth/register")
async def register(username: str = Form(...), password: str = Form(...)):
    existing_user = await db.user.find_one({"username": username})
    if existing_user:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    hashed_password = hash_password(password)
    new_user = {"username": username, "password": hashed_password}
    await db.user.insert_one(new_user)
    return {"message": "Usuario registrado exitosamente"}

# Endpoints de inventario protegidos por JWT
@app.get("/api/v1/inventory", response_model=List[InventoryItem])
async def get_inventory(current_user: str = Depends(get_current_user)):
    items = await db.inventory.find({"user_id": current_user}).to_list(100)
    for item in items:
        item["id"] = str(item["_id"])
    return items

@app.post("/api/v1/inventory", response_model=InventoryItem)
async def create_inventory_item(item: InventoryItem):
    result = await db.inventory.insert_one(item.model_dump())
    item.id = str(result.inserted_id)
    return item

@app.put("/api/v1/inventory/{item_id}", response_model=InventoryItem)
async def update_inventory_item(item: InventoryItem):
    result = await db.inventory.update_one({"_id": ObjectId(item.id)}, {"$set": item.model_dump()})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.delete("/api/v1/inventory/{item_id}")
async def delete_inventory_item(item_id: str):
    result = await db.inventory.delete_one({"_id": ObjectId(item_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted successfully"}
```

**Explicación:**
- Se usa FastAPI para definir endpoints RESTful.
- MongoDB se accede de forma asíncrona con `motor`.
- Las contraseñas se almacenan de forma segura con bcrypt (`passlib`).
- JWT se usa para autenticar y autorizar usuarios.
- Los endpoints de inventario requieren autenticación.

Más sobre FastAPI: [Documentación oficial](https://fastapi.tiangolo.com/)

---

## **Front-End: React + Redux + Context**

El frontend está construido con React, usando Redux para el estado global del inventario y Context para la autenticación. Aquí se muestran los componentes clave:

### **AuthContext.jsx (Gestión de autenticación)**
```jsx
import React, { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
    useEffect(() => {
        const token = localStorage.getItem('token');
        if (token) {
            setIsAuthenticated(true);
        }
    }, []);

    const login = (token) => {
        localStorage.setItem('token', token);
        setIsAuthenticated(true);
    };

    const logout = () => {
        localStorage.removeItem('token');
        setIsAuthenticated(false);
    };

    return (
        <AuthContext.Provider value={{ isAuthenticated, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
```

### **Login.jsx y Register.jsx (Autenticación de usuario)**
Ambos usan el contexto de autenticación y muestran notificaciones amigables:

```jsx
// Fragmento de Login.jsx
const handleLogin = async (values) => {
    setLoading(true);
    try {
        const response = await fetch('http://localhost:8000/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(values),
        });
        const data = await response.json();
        if (response.ok) {
            login(data.token);
            // ...notificación y redirección
        } else {
            // ...manejo de error
        }
    } catch (error) {
        // ...manejo de error
    } finally {
        setLoading(false);
    }
};
```

### **Redux: inventorySlice.js (Gestión de inventario global)**
```js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
export const fetchItems = createAsyncThunk('inventory/fetchItems', async () => {
    const token = localStorage.getItem('token');
    const response = await fetch('http://localhost:8000/api/v1/inventory', {
        headers: { Authorization: `Bearer ${token}` },
    });
    return response.json();
});
// ...addItem, updateItem, deleteItem similares
const inventorySlice = createSlice({
    name: 'inventory',
    initialState: { items: [], loading: false, error: null },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchItems.pending, (state) => { state.loading = true; })
            .addCase(fetchItems.fulfilled, (state, action) => {
                state.loading = false;
                state.items = action.payload;
            });
    },
});
export default inventorySlice.reducer;
```

### **Dashboard.jsx (Vista principal protegida)**
```jsx
import { useAuth } from '../context/AuthContext';
import { useDispatch } from 'react-redux';
import InventoryTable from './InventoryTable';
// ...
const Dashboard = () => {
    const { isAuthenticated, logout } = useAuth();
    const dispatch = useDispatch();
    // ...
    useEffect(() => { dispatch(fetchItems()); }, [dispatch]);
    // ...
    return (
        <Layout>
            {/* Sider, Header, etc. */}
            <InventoryTable onEdit={handleEdit} />
            {/* ... */}
        </Layout>
    );
};
```

---

## **Explicación y buenas prácticas**

- **Seguridad**: Las contraseñas se almacenan con hash seguro (bcrypt). JWT protege los endpoints sensibles. El frontend nunca almacena contraseñas, solo el token.
- **Escalabilidad**: Separar la lógica de negocio (FastAPI) y la vista (React) permite escalar cada parte de forma independiente.
- **Estado global**: Redux centraliza el inventario, Context maneja la sesión.
- **UX**: Ant Design y notificaciones mejoran la experiencia de usuario.

---

## **Recursos adicionales**
- [Documentación oficial de React](https://reactjs.org/docs/getting-started.html)
- [Documentación oficial de FastAPI](https://fastapi.tiangolo.com/)
- [Redux](https://redux.js.org/)
- [MongoDB](https://www.mongodb.com/)