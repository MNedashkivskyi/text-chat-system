from OpenSSL import crypto
import os


class RootCA:

    def __init__(self, ca_path, crl_path):
        self.store = crypto.X509Store()
        self.store.set_flags(crypto.X509StoreFlags.CRL_CHECK)
        if os.path.exists(ca_path):
            self.store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_path, "rb").read()))
        if os.path.exists(crl_path):
            self.store.add_crl(crypto.load_crl(crypto.FILETYPE_PEM, open(crl_path, "rb").read()))

    def verify_cert(self, cert):
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
        context = crypto.X509StoreContext(self.store, cert)
        try:
            context.verify_certificate()
            return True
        except crypto.X509StoreContextError:
            return False





