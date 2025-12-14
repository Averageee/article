#include <boost/asio.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <chrono>

using boost::asio::ip::tcp;

// 获取当前时间字符串
std::string get_current_time() {
	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
	return ss.str();
}

class ChatSession : public std::enable_shared_from_this<ChatSession> {
public:
	explicit ChatSession(tcp::socket socket, int session_id)
		: socket_(std::move(socket)), session_id_(session_id), streambuf_(), first_message_is_password_(true) {
		std::cout << "[" << get_current_time() << "] 新客户端连接 (会话ID: " << session_id_ << ")\n";
	}

	void start() {
		read_next_message();
	}

	void send_message(const std::string &message) {
		auto self = shared_from_this();
		std::string full_message = "[服务器] " + message + "\n";
		boost::asio::async_write(
			socket_, boost::asio::buffer(full_message),
			[self](const boost::system::error_code &ec, std::size_t /*bytes_transferred*/) {
				if (ec) {
					if (ec != boost::asio::error::operation_aborted) {
						std::cerr << "[" << get_current_time() << "] 发送消息错误: " << ec.message() << "\n";
					}
				}
			});
	}

private:
	static bool try_parse_number(const std::string &text, long long &out) {
		try {
			std::size_t idx = 0;
			long long value = std::stoll(text, &idx, 10);
			if (idx != text.size()) return false;
			out = value;
			return true;
		} catch (...) {
			return false;
		}
	}

	void read_next_message() {
		auto self = shared_from_this();
		boost::asio::async_read_until(
			socket_, streambuf_, '\n',
			[self](const boost::system::error_code &ec, std::size_t bytes_transferred) {
				if (ec) {
					if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted) {
						std::cerr << "[" << get_current_time() << "] 读取错误: " << ec.message() << "\n";
					}
					std::cout << "[" << get_current_time() << "] 客户端断开连接 (会话ID: " << self->session_id_ << ")\n";
					return;
				}

				std::istream is(&self->streambuf_);
				std::string line;
				line.resize(bytes_transferred);
				is.read(&line[0], static_cast<std::streamsize>(bytes_transferred));

				// 移除换行和回车
				if (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
					while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
				}

				if (self->first_message_is_password_) {
					self->first_message_is_password_ = false;
					long long pw = 0;
					if (try_parse_number(line, pw)) {
						long long result = pw * 10;
						std::cout << "[" << get_current_time() << "] 会话 " << self->session_id_ << " 密码*10 = " << result << "\n";
						self->send_message(std::string("密码*10 = ") + std::to_string(result));
					} else {
						std::cout << "[" << get_current_time() << "] 会话 " << self->session_id_ << " 首条消息不是纯数字密码: '" << line << "'\n";
						self->send_message("首条消息应为数字密码");
					}
				} else {
					std::cout << "[" << get_current_time() << "] 客户端 " << self->session_id_ << " 说: " << line << "\n";
					self->send_message("收到你的消息: " + line);
				}

				self->read_next_message();
			});
	}

	tcp::socket socket_;
	int session_id_;
	boost::asio::streambuf streambuf_;
	bool first_message_is_password_;
};

class ChatServer {
public:
	ChatServer(boost::asio::io_context &io_context, unsigned short port)
		: io_context_(io_context), acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), next_session_id_(1) {
		start_accept();
		std::cout << "[" << get_current_time() << "] 聊天服务器启动，监听端口 " << port << "\n";
		std::cout << "[" << get_current_time() << "] 等待客户端连接...\n";
	}

	void broadcast_message(const std::string &message) {
		for (auto &session : active_sessions_) {
			if (auto session_ptr = session.lock()) {
				session_ptr->send_message(message);
			}
		}
	}

private:
	void start_accept() {
		acceptor_.async_accept([this](const boost::system::error_code &ec, tcp::socket socket) {
			if (!ec) {
				auto session = std::make_shared<ChatSession>(std::move(socket), next_session_id_++);
				active_sessions_.push_back(session);

				active_sessions_.erase(
					std::remove_if(active_sessions_.begin(), active_sessions_.end(),
						[](const std::weak_ptr<ChatSession> &wp) { return wp.expired(); }),
					active_sessions_.end());

				session->start();
			} else {
				std::cerr << "[" << get_current_time() << "] 接受连接错误: " << ec.message() << "\n";
			}
			start_accept();
		});
	}

	boost::asio::io_context &io_context_;
	tcp::acceptor acceptor_;
	std::vector<std::weak_ptr<ChatSession>> active_sessions_;
	int next_session_id_;
};

int main(int argc, char *argv[]) {
	try {
		unsigned short port = 12345;
		if (argc >= 2) {
			port = static_cast<unsigned short>(std::stoi(argv[1]));
		}

		boost::asio::io_context io_context;
		ChatServer server(io_context, port);

		std::thread input_thread([&io_context, &server]() {
			std::string line;
			while (std::getline(std::cin, line)) {
				if (line == "quit" || line == "exit") {
					std::cout << "[" << get_current_time() << "] 服务器正在关闭...\n";
					io_context.stop();
					break;
				}
				if (!line.empty()) {
					server.broadcast_message(line);
					std::cout << "[" << get_current_time() << "] 服务器广播: " << line << "\n";
				}
			}
		});

		io_context.run();

		if (input_thread.joinable()) {
			input_thread.join();
		}

		std::cout << "[" << get_current_time() << "] 服务器已关闭\n";
	} catch (const std::exception &ex) {
		std::cerr << "[" << get_current_time() << "] 致命错误: " << ex.what() << "\n";
		return 1;
	}
	return 0;
}
