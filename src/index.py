from api import create_server


if __name__ == "__main__":
    server = create_server()
    print("违规飞行案件后端已启动", flush=True)
    server.serve_forever()
