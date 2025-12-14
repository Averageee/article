#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <ctime>
#include <iomanip>
#include <sstream>

using boost::asio::ip::tcp;

// 获取当前时间字符串
std::string get_current_time() {
	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
	return ss.str();
}

class ChatClient {
public:
	ChatClient(boost::asio::io_context &io_context, const std::string &host, const std::string &port)
		: io_context_(io_context), socket_(io_context), host_(host), port_(port), connected_(false) {}

	bool connect() {
		try {
			tcp::resolver resolver(io_context_);
			auto endpoints = resolver.resolve(host_, port_);
			boost::asio::connect(socket_, endpoints);
			connected_ = true;
			std::cout << "[" << get_current_time() << "] 成功连接到服务器 " << host_ << ":" << port_ << "\n";

			// 连接成功后提示输入密码，并立即发送到服务器
			std::cout << "请输入密码: ";
			std::string password;
			std::getline(std::cin, password);
			password.push_back('\n');
			boost::system::error_code pw_ec;
			boost::asio::write(socket_, boost::asio::buffer(password), pw_ec);
			if (pw_ec) {
				std::cerr << "[" << get_current_time() << "] 发送密码失败: " << pw_ec.message() << "\n";
			}

			std::cout << "[" << get_current_time() << "] 输入 'quit' 或 'exit' 退出程序\n";
			std::cout << "[" << get_current_time() << "] 开始聊天...\n\n";
			return true;
		} catch (const std::exception &e) {
			std::cerr << "[" << get_current_time() << "] 连接失败: " << e.what() << "\n";
			return false;
		}
	}

	void start() {
		if (!connected_) {
			std::cerr << "[" << get_current_time() << "] 客户端未连接，无法启动\n";
			return;
		}

		// 启动异步读取
		start_async_read();

		// 启动用户输入处理
		std::thread input_thread([this]() {
			std::string line;
			while (connected_ && std::getline(std::cin, line)) {
				if (line == "quit" || line == "exit") {
					std::cout << "[" << get_current_time() << "] 正在断开连接...\n";
					connected_ = false;
					break;
				}
				if (!line.empty()) {
					send_message(line);
				}
			}
			// 关闭发送端
			boost::system::error_code ignored;
			socket_.shutdown(tcp::socket::shutdown_send, ignored);
		});

		// 运行IO上下文
		io_context_.run();

		if (input_thread.joinable()) {
			input_thread.join();
		}
	}

private:
	void start_async_read() {
		boost::asio::async_read_until(
			socket_, read_buffer_, '\n',
			[this](const boost::system::error_code &ec, std::size_t bytes_transferred) {
				if (ec) {
					if (ec != boost::asio::error::operation_aborted && ec != boost::asio::error::eof) {
						std::cerr << "[" << get_current_time() << "] 读取错误: " << ec.message() << "\n";
					}
					connected_ = false;
					return;
				}

				std::istream is(&read_buffer_);
				std::string line;
				line.resize(bytes_transferred);
				is.read(&line[0], static_cast<std::streamsize>(bytes_transferred));

				// 移除换行符
				if (!line.empty() && line.back() == '\n') {
					line.pop_back();
				}

				std::cout << "[" << get_current_time() << "] " << line << "\n";

				// 继续读取
				if (connected_) {
					start_async_read();
				}
			});
	}

	void send_message(const std::string &message) {
		if (!connected_) return;

		std::string full_message = message + "\n";
		boost::asio::async_write(
			socket_, boost::asio::buffer(full_message),
			[this, message](const boost::system::error_code &ec, std::size_t /*bytes_transferred*/) {
				if (ec) {
					if (ec != boost::asio::error::operation_aborted) {
						std::cerr << "[" << get_current_time() << "] 发送消息错误: " << ec.message() << "\n";
						connected_ = false;
					}
				} else {
					std::cout << "[" << get_current_time() << "] 你: " << message << "\n";
				}
			});
	}

	boost::asio::io_context &io_context_;
	tcp::socket socket_;
	std::string host_;
	std::string port_;
	boost::asio::streambuf read_buffer_;
	std::atomic<bool> connected_;
};

int main(int argc, char *argv[]) {
	try {
		const char *host = "127.0.0.1";
		const char *port = "12345";

		if (argc >= 2) host = argv[1];
		if (argc >= 3) port = argv[2];

		std::cout << "=== C++ 聊天客户端 ===\n";
		std::cout << "正在连接到服务器 " << host << ":" << port << "...\n";

		boost::asio::io_context io_context;
		ChatClient client(io_context, host, port);

		if (client.connect()) {
			client.start();
		} else {
			std::cerr << "[" << get_current_time() << "] 无法连接到服务器，程序退出\n";
			return 1;
		}

		std::cout << "[" << get_current_time() << "] 客户端已断开连接\n";
	} catch (const std::exception &ex) {
		std::cerr << "[" << get_current_time() << "] 致命错误: " << ex.what() << "\n";
		return 1;
	}
	return 0;
}
