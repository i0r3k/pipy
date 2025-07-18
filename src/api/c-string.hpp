/*
 *  Copyright (c) 2019 by flomesh.io
 *
 *  Unless prior written consent has been obtained from the copyright
 *  owner, the following shall not be allowed.
 *
 *  1. The distribution of any source codes, header files, make files,
 *     or libraries of the software.
 *
 *  2. Disclosure of any source codes pertaining to the software to any
 *     additional parties.
 *
 *  3. Alteration or removal of any notices in or on the software or
 *     within the documentation included within the software.
 *
 *  ALL SOURCE CODE AS WELL AS ALL DOCUMENTATION INCLUDED WITH THIS
 *  SOFTWARE IS PROVIDED IN AN “AS IS” CONDITION, WITHOUT WARRANTY OF ANY
 *  KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef API_C_STRING_HPP
#define API_C_STRING_HPP

#include "pjs/pjs.hpp"
#include "data.hpp"

namespace pipy {

//
// CString
//

class CString : public pjs::ObjectTemplate<CString> {
public:
  auto size() const -> int { return m_data->size(); }
  auto data() const -> Data* { return m_data; }

  auto to_str() -> pjs::Str*;

  virtual auto to_string() const -> std::string override {
    return m_data->to_string();
  }

protected:
  CString();
  CString(const std::string &str);
  CString(const Data &data);

private:
  pjs::Ref<Data> m_data;
  pjs::Ref<pjs::Str> m_str;

  friend class pjs::ObjectTemplate<CString>;
};

} // namespace pipy

#endif // API_C_STRING_HPP
