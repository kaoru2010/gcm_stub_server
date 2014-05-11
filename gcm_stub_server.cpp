/*
   Copyright 2014 Kaoru Yanase

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <signal.h>
#include <stdexcept>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/array.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio/coroutine.hpp>
#include <http_header.h>

using namespace std;

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class buffer_size_at_least
{
public:
    explicit buffer_size_at_least(ptrdiff_t length) : length_(length) {}

    template <typename Iterator>
    std::pair<Iterator, bool> operator()(Iterator begin, Iterator end) const
    {
        return std::make_pair(begin + length_, distance(begin, end) >= length_);
    }

private:
    ptrdiff_t length_;
};

namespace boost {
    namespace asio {
        template <> struct is_match_condition<buffer_size_at_least> : public boost::true_type {};
    } // namespace asio
} // namespace boost

class gcm_fake_server;
class gcm_session;

class response_handler : boost::asio::coroutine
{
public:
    explicit response_handler(gcm_fake_server *);
    void operator()(const boost::system::error_code& ec = boost::system::error_code(), std::size_t bytes_transferred = -1);
private:
    gcm_fake_server *server_;
    boost::shared_ptr<gcm_session> session_;
};

class gcm_fake_server
{
public:
    gcm_fake_server(boost::asio::io_service& io_service, unsigned short port)
    :   io_service_(io_service)
    ,   port_(port)
    ,   acceptor_(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
    ,   context_(boost::asio::ssl::context::sslv23)
    ,   socket_(io_service, context_)
    ,   handler_(this)
    {
        context_.set_options(boost::asio::ssl::context::default_workarounds);
        context_.use_certificate_chain_file("server.pem");
        context_.use_private_key_file("server-no-password.pem", boost::asio::ssl::context::pem);
    }

    void start_accept()
    {
        handler_(boost::system::error_code());
    }

private:
    boost::asio::io_service& io_service_;
    unsigned short port_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context context_;
    ssl_socket socket_;
    response_handler handler_;

    friend class response_handler;
};

class gcm_session
{
public:
    gcm_session(boost::asio::io_service& io_service, boost::asio::ssl::context& context)
    :   io_service_(io_service)
    ,   context_(context)
    ,   socket_(io_service, context)
    ,   buf_()
    ,   http_header_()
    {}

    template<typename Handler>
    void async_read_header(Handler handler)
    {
        auto internal_handler = [handler, this](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable
        {
            if (!ec) {
                parse_status_line(&http_header_, boost::asio::buffer_cast<const char *>(buf_.data()), bytes_transferred);
                buf_.consume(bytes_transferred + 4);
            }
            handler(ec, bytes_transferred);
        };

        async_read_until(socket_, buf_, "\r\n\r\n", internal_handler);
    }

    template<typename Handler>
    void async_read_body(Handler handler)
    {
        auto internal_handler = [handler, this](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable
        {
            if (!ec) {
                buf_.consume(http_header_.content_length);
            }
            handler(ec, bytes_transferred);
        };

        async_read_until(socket_, buf_, buffer_size_at_least(http_header_.content_length), internal_handler);
    }

private:
    boost::asio::io_service& io_service_;
    boost::asio::ssl::context& context_;
    ssl_socket socket_;
    boost::asio::streambuf buf_;
    http_header_context_t http_header_;

    friend class response_handler;
};

inline
response_handler::response_handler(gcm_fake_server *server)
:   server_(server)
,   session_()
{
}

#include <boost/asio/yield.hpp>
inline
void response_handler::operator()(const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    namespace asio = boost::asio;

    if (ec)
        return;

    reenter(this) {
        do {
            session_.reset(new gcm_session(server_->io_service_, server_->context_));
            yield server_->acceptor_.async_accept(session_->socket_.lowest_layer(), *this);
            cout << "new connection" << endl;
            fork response_handler(*this)();
        } while(is_parent());

        yield session_->socket_.async_handshake(asio::ssl::stream_base::server, *this);
        cout << "handshake" << endl;

        {
            // Read status line and headers
            yield session_->async_read_header(*this);

            // Read POST bosy
            yield session_->async_read_body(*this);

            // Write response
            yield asio::async_write(session_->socket_, asio::buffer("HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nOK\n"), *this);
        }
    }
}
#include <boost/asio/unyield.hpp>

int main()
{
    boost::asio::io_service io_service;

    // Wait for signals indicating time to shut down.
    boost::asio::signal_set signals(io_service);
    signals.add(SIGINT);
    signals.add(SIGTERM);
#if defined(SIGQUIT)
    signals.add(SIGQUIT);
#endif // defined(SIGQUIT)
    signals.async_wait(boost::bind(
          &boost::asio::io_service::stop, &io_service));

    gcm_fake_server s(io_service, 10443);
    s.start_accept();

    io_service.run();

    return 0;
}
