import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:3005/api",
  withCredentials: true, // if you want cookies in the future
});

export default api;
