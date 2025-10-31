#!/usr/bin/env python3
"""
Dynamic ODL Network Visualizer (Thread-safe Auto Update)
This version fixes Tkinter threading issues by using root.after() to safely update GUI from background threads.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import threading
import time

ODL_HOST = "localhost"
ODL_PORT = 8181
USERNAME = "admin"
PASSWORD = "admin"
RIB_NAME = "bgp-to-r1"


class ODLVisualizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Dynamic ODL Network Visualizer")
        self.root.geometry("1100x750")
        self.root.configure(bg="#2C3E50")

        self.routes = []
        self.router_status = {}
        self.refresh_interval = 100  # seconds
        self.auto_refresh_running = False

        self.setup_gui()

    def setup_gui(self):
        header = tk.Frame(self.root, bg="#44195E", height=100)
        header.pack(fill=tk.X, padx=10, pady=10)
        tk.Label(header, text="Dynamic ODL Network Visualizer",
                 font=("Arial", 22, "bold"), bg="#34495E", fg="white").pack(pady=10)
        tk.Label(header, text=f"Controller: {ODL_HOST}:{ODL_PORT}",
                 font=("Arial", 10), bg="#34495E", fg="#BDC3C7").pack()

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#2C3E50")
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Button(btn_frame, text="Fetch & Visualize", font=("Arial", 13, "bold"),
                  command=lambda: self.run_visualization(update_only=False), width=20, bg="#3498DB",
                  fg="white", relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Show Router Info", font=("Arial", 13, "bold"),
                  command=self.show_router_info, width=20, bg="#27AE60",
                  fg="white", relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="Toggle Auto Update", font=("Arial", 13, "bold"),
                  command=self.toggle_auto_refresh, width=20, bg="#E67E22",
                  fg="white", relief="flat", cursor="hand2").pack(side=tk.LEFT, padx=10)

        # Output Panel
        display = tk.Frame(self.root, bg="#34495E")
        display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output = scrolledtext.ScrolledText(display, wrap=tk.WORD, font=("Consolas", 11),
                                                bg="#ECF0F1", fg="#2C3E50")
        self.output.pack(fill=tk.BOTH, expand=True)

        self.status = tk.Label(self.root, text="Ready", bg="#34495E", fg="white",
                               font=("Arial", 10), anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_auto_refresh(self):
        """Enable or disable periodic topology updates."""
        if not self.auto_refresh_running:
            self.auto_refresh_running = True
            threading.Thread(target=self.auto_refresh_loop, daemon=True).start()
            self.status.config(text="Auto-update: ON")
            self.output.insert(tk.END, "Auto-update started.\n")
        else:
            self.auto_refresh_running = False
            self.status.config(text="Auto-update: OFF")
            self.output.insert(tk.END, "Auto-update stopped.\n")

    def auto_refresh_loop(self):
        """Continuously refresh network state at intervals."""
        while self.auto_refresh_running:
            # Schedule run_visualization(update_only=True) safely on main thread
            self.root.after(0, self.run_visualization, True)
            time.sleep(self.refresh_interval)

    def run_visualization(self, update_only=False):
        """Fetch ODL data or fallback to local JSON."""
        if not update_only:
            self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "Fetching BGP data from ODL...\n")

        url = f"http://{ODL_HOST}:{ODL_PORT}/rests/data/bgp-rib:bgp-rib/rib={RIB_NAME}?content=nonconfig"
        try:
            response = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), timeout=8)
            if response.status_code == 200:
                data = response.json()
                self.output.insert(tk.END, "Successfully fetched data from ODL.\n")
                self.update_topology(data, update_only)
            else:
                raise Exception(f"HTTP Error {response.status_code}")

        except Exception as e:
            self.output.insert(tk.END, f"Error: {e}\n")
            # Fallback: load from local backup
            try:
                if os.path.exists("ODL_RES.json"):
                    with open("ODL_RES.json", "r") as f:
                        data = json.load(f)
                    self.output.insert(tk.END, "Using local ODL_RES.json backup.\n")
                    self.update_topology(data, update_only)
                else:
                    self.output.insert(tk.END, "Local backup file ODL_RES.json not found.\n")
            except Exception as err:
                self.output.insert(tk.END, f"Local file read error: {err}\n")

    def update_topology(self, data, update_only=False):
        self.routes = self.extract_routes(data)
        if not self.routes:
            self.output.insert(tk.END, "No routes found.\n")
            return
        self.refresh_router_status(self.routes)
        G = self.build_graph(self.routes)
        # Schedule visualization display on main thread always
        self.root.after(0, self.display_graph, G)
        if not update_only:
            self.output.insert(tk.END, "Topology visualization generated successfully.\n")

    def extract_routes(self, data):
        """Extract all IPv4 routes safely."""
        routes = []
        try:
            rib_list = data.get("bgp-rib:rib", [])
            if not isinstance(rib_list, list) or not rib_list:
                return routes
            loc_rib = rib_list[0].get("loc-rib", {})
            tables = loc_rib.get("tables", [])
            if not tables:
                return routes
            ipv4_routes = tables[0].get("bgp-inet:ipv4-routes", {}).get("ipv4-route", [])
            for route in ipv4_routes:
                prefix = route.get("prefix")
                nh = route.get("attributes", {}).get("ipv4-next-hop", {}).get("global")
                origin = route.get("attributes", {}).get("origin", {}).get("value")
                med = route.get("attributes", {}).get("multi-exit-disc", {}).get("med")
                local_pref = route.get("attributes", {}).get("local-pref", {}).get("pref")
                routes.append({
                    "prefix": prefix,
                    "next_hop": nh,
                    "origin": origin,
                    "med": med,
                    "local_pref": local_pref
                })
            return routes
        except Exception as e:
            self.output.insert(tk.END, f"Route parsing error: {e}\n")
            return routes

    def refresh_router_status(self, routes):
        """Track online/offline routers."""
        active_nodes = {r["next_hop"] for r in routes if r["next_hop"]}
        # Mark previously known routers offline if missing now
        for rtr in list(self.router_status.keys()):
            if rtr not in active_nodes:
                self.router_status[rtr] = "Offline"
        # Mark current active routers online
        for nh in active_nodes:
            self.router_status[nh] = "Online"

    def build_graph(self, routes):
        """Construct the visualized network graph."""
        G = nx.Graph()
        for route in routes:
            nh = route.get("next_hop")
            prefix = route.get("prefix")
            if nh:
                node_color = (
                    "#27AE60" if self.router_status.get(nh, "Online") == "Online" else "#E74C3C"
                )
                G.add_node(nh, color=node_color)
                G.add_node(prefix, color="#3498DB")
                G.add_edge(nh, prefix, label=f"via {nh}")
        return G

    def display_graph(self, G):
        """Display network graph."""
        if not G.nodes:
            messagebox.showwarning("No Data", "No topology data to display.")
            return
        plt.clf()
        topo_window = tk.Toplevel(self.root)
        topo_window.title("Live BGP Route Topology")
        topo_window.geometry("900x700")

        pos = nx.spring_layout(G, seed=42)
        colors = [G.nodes[n].get("color", "#3498DB") for n in G.nodes()]
        plt.figure(figsize=(9, 7))
        nx.draw(G, pos, with_labels=True, node_color=colors, node_size=1800,
                font_size=9, font_weight="bold", edgecolors="black")
        nx.draw_networkx_edge_labels(G, pos, edge_labels=nx.get_edge_attributes(G, "label"), font_size=8)
        plt.title("Dynamic IPv4 Route Topology", fontsize=14, fontweight="bold")
        plt.axis("off")

        canvas = FigureCanvasTkAgg(plt.gcf(), master=topo_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close()

    def show_router_info(self):
        """Show router status and details."""
        info_window = tk.Toplevel(self.root)
        info_window.title("Router Information")
        info_window.geometry("500x400")

        frame = ttk.Frame(info_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        tree = ttk.Treeview(frame, columns=("Router", "Status"), show="headings")
        tree.heading("Router", text="Router / Next-Hop")
        tree.heading("Status", text="Status")
        tree.pack(fill=tk.BOTH, expand=True)

        for router, status in self.router_status.items():
            tree.insert("", tk.END, values=(router, status))

        ttk.Label(info_window, text="Routers dynamically updated based on ODL data.",
                  font=("Arial", 10)).pack(pady=5)


def main():
    root = tk.Tk()
    app = ODLVisualizer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
