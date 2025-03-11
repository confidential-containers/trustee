if [ $(uname) == "Darwin" ]
then
  _base64="base64"
  _sed="gsed"
  _tokenise="mac_tokenise"
else
  _base64="base64 -w0"
  _sed="sed"
  _tokenise="linux_tokenise"
fi

function mac_tokenise() {
  local token="$1"

  od -v -t u1 "${token}" \
    | cut -c11- \
    | tr -s '[:blank:]' '\n' \
    | ${_sed} -e 's/$/,/' \
    | ${_sed} -e '$s/,//' \
    | tr -d '\n'
}

function linux_tokenise() {
  local token="$1"

  od -v -w1 -t u1 ${token} \
    | cut -c9- \
    | ${_sed} -e 's/$/,/' \
    | ${_sed} '$d' \
    | ${_sed} -e '$s/,//' \
    | tr -d '\n'
}

base64url_encode() {
	${_base64} \
		| tr '+/' '-_' \
		| tr -d '=';
}

base64url_decode() {
	awk '{ if (length($0) % 4 == 3) print $0"="; else if (length($0) % 4 == 2) print $0"=="; else print $0; }' \
		| tr -- '-_' '+/' \
		| base64 -d;
}
