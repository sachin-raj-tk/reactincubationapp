import React from "react";
import { Toaster } from "react-hot-toast";
import {BrowserRouter , Routes, Route} from 'react-router-dom'
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";

function App() {
  return (
    <BrowserRouter>
     <Toaster position="top-center" reverseOrder={false}/>
      <Routes>
        <Route path="/login" element={<Login/>}/>
        <Route path="/register" element={<Register/>}/>
        <Route path="/" element={<Home/>}/>

      </Routes>
    </BrowserRouter>
  );
}

export default App;
