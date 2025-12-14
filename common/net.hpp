#pragma once
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <sstream>
#include <string>

namespace net {
    using boost::asio::ip::tcp;

    inline std::string ptree_to_json(const boost::property_tree::ptree &pt){
        std::ostringstream oss; boost::property_tree::write_json(oss, pt, false);
        std::string s = oss.str();
        if(!s.empty() && s.back() != '\n') s.push_back('\n');
        return s;
    }
    inline boost::property_tree::ptree json_to_ptree(const std::string &s){
        std::istringstream iss(s);
        boost::property_tree::ptree pt; boost::property_tree::read_json(iss, pt);
        return pt;
    }
    inline std::string read_line(boost::asio::ip::tcp::socket &socket){
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, '\n');
        std::istream is(&buf);
        std::string line; std::getline(is, line);
        return line;
    }
    inline void write_line(boost::asio::ip::tcp::socket &socket, const std::string &line){
        std::string s = line;
        if(s.empty() || s.back() != '\n') s.push_back('\n');
        boost::asio::write(socket, boost::asio::buffer(s));
    }
}

