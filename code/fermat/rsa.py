import numpy as np
import random
import hashlib

class RSA:
    """
    RSA implementation for encryption, signature and station-to-station key exchange.
    """

    def __init__(self, private_key: int = None, public_key: int = None, n: int = None):
        self.private_key = private_key
        self.public_key = public_key
        self.n = n
        self.challenge = "Bravo ! Je suis épousplouffé par ta maîtrise du timing attack sur RSA !"

    def setKeys(self, private_key: int, public_key: int, n: int) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.n = n

    def getKeys(self) -> list:
        return [self.public_key, self.n], [self.private_key, self.n]
    
    def exportPublicKey(self) -> list:
        return [self.public_key, self.n]

    def createKeyPair(self, size: int) -> list:
        p = self.primary_nb_generator(2**(size//2-1), 2**size//2)
        q = self.primary_nb_generator(2**(size//2-1), 2**size//2)
        n, e, d = self.key_generator(p, q)
        self.setKeys(d, e, n)
        return [n, e, d]

    def encrypt(self, message: int) -> int:
        return self.fast_exp(message, self.public_key, self.n)

    def decrypt(self, cipher: int, private_key: int = None) -> int:
        if private_key is not None:
            return self.fast_exp(cipher, private_key, self.n)
        return self.fast_exp(cipher, self.private_key, self.n)
    
    def createChallenge(self) -> int:
        challenge_int = int.from_bytes(self.challenge.encode(), 'big')
        self.challenge = self.encrypt(challenge_int)
        return self.challenge
    
    def decryptChallenge(self, tested_key: int) -> str:
        decrypted_challenge_int = self.decrypt(self.challenge, private_key=tested_key)
        decrypted_challenge_bytes = decrypted_challenge_int.to_bytes((decrypted_challenge_int.bit_length() + 7) // 8, 'big')
        return decrypted_challenge_bytes.decode()

    def fast_exp(self, y: int, x: int, n: int) -> int:
        """
        Apply fast exponentiation for y^x modulo n

        Parameters
        ----------
        y : int
            Number
        x : int
            Power
        n : int
            Modulo

        Returns
        -------
        int
            Result of fast exponentiation

        """
        s = 1
        y %= n

        while x > 0:
            if (x % 2) == 1:
                s = (s * y) % n
            y = (y * y) % n
            x = x >> 1

        return s

    def fermat_test(self, n: int) -> bool:
        """
        Check if a number is primary by running Fermat test.

        Parameters
        ----------
        n : int
            Number to check

        Returns
        -------
        bool
            True if the number is primary

        """
        for i in range(20):
            alpha = random.randint(2, n - 1)
            if self.fast_exp(alpha, n - 1, n) != 1:
                return False
        return True

    def primary_nb_generator(self, a: int, b: int, safe_prime: bool = False) -> int:
        """
        Generate primary number in range a, b

        Parameters
        ----------
        a : int
            lower bound
        b : int
            upper bound
        safe_prime : bool
            Generate primary number p with (p - 1) / 2 also primary

        Returns
        -------
        int
            Primary number generated

        """
        while True:
            p = random.randint(a, b)
            if self.fermat_test(p):
                if safe_prime:
                    if self.fermat_test((p - 1) / 2):
                        return p
                else:
                    return p

    def Euclide(self, a: int, b: int) -> list:
        """
        Euclide's extended algorithm, used to find decryption exponent d for RSA

        Parameters
        ----------
        a : int
            Number
        b : int
            Number

        Returns
        -------
        list
            A list [pgcd(a, b), inverse of a mod b, inverse of b mod a]

        """
        if b > a:
            a, b = b, a  # swap

        r_0, r_1 = a, b
        s_0, s_1 = 1, 0
        t_0, t_1 = 0, 1

        while r_1 != 0:
            q = r_0 // r_1
            r_0, r_1 = r_1, r_0 - q * r_1
            s_0, s_1 = s_1, s_0 - q * s_1
            t_0, t_1 = t_1, t_0 - q * t_1

        return [r_0, s_0 % b, t_0 % a]

    def key_generator(self, p: int = 0, q: int = 0, e: int = 0) -> list:
        """
        Generate public and private key for RSA

        Returns
        -------
        list
            modulo, public, private key

        """
        if p == 0:
            p = self.primary_nb_generator(2**511, 2**512)
        if q == 0:
            q = self.primary_nb_generator(2**511, 2**512)

        assert self.fermat_test(p), "p is not primary"
        assert self.fermat_test(q), "q is not primary"
        n = p * q
        phi_n = (p - 1) * (q - 1)

        if e != 0:
            pgcd, _, d = self.Euclide(phi_n, e)
            assert pgcd == 1, "pgcd(phi_n, e) is not equal to 1, so no private key found !"

        else:
            # Find a primary number e with phi_n
            while True:
                e = random.randint(2**511, 2**512)
                pgcd, _, d = self.Euclide(phi_n, e)

                # If primary number with phi_n, claim public key
                if pgcd == 1:
                    break
        return n, e, d

    def get_digest(self, message: int) -> str:
        """
        Return sha256 digest from the given message

        Parameters
        ----------
        message : int
            Message

        Returns
        -------
        str
            sha256 digest

        """
        # Ensure upper round is made with the +7
        size = (message.bit_length() + 7) // 8
        message_in_bytes = message.to_bytes(size, 'big')
        return hashlib.sha256(message_in_bytes).hexdigest()

    def sign(self, message: int, key: int, n: int) -> int:
        """
        Sign the give message with the given key (key, n)

        Parameters
        ----------
        message : int
            Message to sign
        key : int
            Key used to sign message
        n : int
            Modulo corresponding to the given key

        Returns
        -------
        int
            The message signed

        """
        digest = self.get_digest(message)
        return self.fast_exp(int(digest, base=16), key, n)

    def check_signature(self, message: int, signature: int, key: int, n: int) -> bool:
        """
        Check integrity of given message according to signature

        Parameters
        ----------
        message : int
            check integrity of message
        signature : int
            signature used to check integrity of message
        key : int
            key used to decrypt signature
        n : int
            modulo corresponding to the given key

        Returns
        -------
        bool
            True if integrity of message is configured

        """
        digest = int(self.get_digest(message), 16)
        sign = self.fast_exp(signature, key, n)
        if digest == sign:
            print("Signature verified !")
            return True
        print("Signature not verified !")
        return False

if __name__ == "__main__":

    #----------------------------------------------------------------------------
    # Examples values
    #----------------------------------------------------------------------------

    # for RSA encryption :

    p_A = 13109499994810966779468866046493465498469807493634236479294124421385342920350717814807375283698575766763256101470694189234369358996750113963585617491399169
    q_A = 9497561827984502554523100157901534504433126034087863778629488755692649311435921364240405549590851856701860175924335776598684751639633322074428628372725777
    n_A = p_A * q_A
    e_A = 4574830074548708213
    m_1 = 123456789132456789

    # Expected results :
    # 1) Check if p and q are indeed prime, then compute d_A and the ciphertext.
    # 2) Expected values for d_A and the ciphertext (d_A is also used for station-to-station later)
    d_A = 1685394382767324790326942621450485552187209875614438478305225564629345944620726038114923060947436330701451901921041511234432041036987266468290187679773130363479895993621867708066144608084390089775045890165825736468637468786667820591136139480545376198614216373031208691260339805721685482401743494212035728605
    # cipher = 32468932964181322647810913060097066975304467072050643211304428656476623133068329653886195740426516038144100129255895281039142864272296799126753030014464755203797098445143314298922512718785433009136404533290100525054356166805463645892708927694801117827432767298393815743170470207262077229267156532545837844746
    # 3) And show the decryption indeed finds the correct message m_1.


    # for RSA signatures :

    p_B = 10826236673044680963399044397492990517950100496226253527517396594056941773100235891495996442661607934789334573338262984224575279140723546671909015161165841
    q_B = 13068724959497413087750499937723404386396234752223421227108292956808841500055256288126351713047692004275186905392145633277656168051780140711564635964305603
    n_B = p_B * q_B
    e_B = 15363431916099183937
    d_B = 99028653602245779845285312307808515171286419911090461439401679147183594769788570637862858627361848873110757184618159656805126920324532303690918472435585415644809804509292960212584309940116204022655165333574427857625598512132465843176880573701404843875750652856715151972981401483364420748866785456380681449953
    m_2 = 999888777666555444333222111000


    # Expected results :
    # 1) Compute the signature, which should have the following result :
    # Signature = 139946149260693867607112906574735868062749437621729152371217474062708529251204743665018991444038005832618912915250036414898959900238801293242485481120544999182886616669733899259575955678176133539745600054828147224713714471521374309679085794180533135483883902152178064817185104702608162450188184338147593819800
    # 2) And don't forget to test the verification of the signature.


    # Finally, for station to station :

    pub_Alice = [e_A, n_A]
    priv_Alice = [d_A, n_A]
    pub_Bob = [e_B, n_B]
    priv_Bob = [d_B, n_B]
    safe_prime = 2004890248675962691713190610809938766185621168064979413365812239027511292529980906463903581678786848688704872949028858842995789224512221900227664478944051223
    alpha = 5
    x = 1061775670328897479642045825518654602578846023540121012631031945572796572947245459955958771884051774545117531495156990657757207018855371855532676140389741288
    y = 392417823113702585344984211877708879159301551909174807442181089475282662900844681918382176814109732720706300601726300762268420191278884678744009799141009819


    # Expected results :
    # Proceed to the pseudo Station-to-Station key generation, with every step,
    # computing the following elements :
    # 1) alpha^x mod p (from Alice) = 686072914171234798069517712764277594421530837248520761454562297567737629274501846654087857110320672185192257738624560988240804394506647168646502643636056310
    # 2) alpha^y mod p (from Bob) = 1658758911043428653679670657159403893659858431555423238518923992311175752537434444470667284622227826513095646428663996761247179634768488071743521322105826864
    # 3) session_key K = 133319045406894848338625909766918081728670119580456005459847062820377364927299550101232531204505214272971383981615061959224396184823089732799942062031596841
    # 4) Signature from Bob on (alpha^x, alpha^y, K) = 63637939875901691094764242278906665544983903077054207988218710640087544761228273045150821483357729338737390290548046762350697337909101721771119707350314342587290126983794881205873189463125171775729781807366888186695684820979887485019292913876833243417638388536805972736525678021591270150561199609942649208004
    # 5) Signature from Alice on (alpha^y, alpha^x, K) = 45467152564432701103620506688535942942709188195272432989568457473601022575230584678514742692432145004914876272400870285574876815019240848540253393082439483176306291410816134069425004279929786767259112836051752427213131534826834152132670963428804617973787768260686245775875564276853832786703782164483812397373
    # 6) Don't forget that Alice has to verify Bob's signature, and vice-versa !


    print("\n=============== RSA ENCRYPTION ===============\n")

    RSA_instance = RSA()
    n, e, d = RSA_instance.key_generator(p_A, q_A, e_A)
    assert d == d_A, "Private key generated is different from the expected key !"

    print(f"Message:                {m_1}\n")

    cipher = RSA_instance.fast_exp(m_1, e, n)
    assert cipher == 32468932964181322647810913060097066975304467072050643211304428656476623133068329653886195740426516038144100129255895281039142864272296799126753030014464755203797098445143314298922512718785433009136404533290100525054356166805463645892708927694801117827432767298393815743170470207262077229267156532545837844746, "Encrypted message is not correct !"
    print(f"Ciphertext:             {cipher}\n")

    recovered_message = RSA_instance.fast_exp(cipher, d, n)
    assert recovered_message == m_1, "Recovered message is different from original message !"
    print(f"Decrypted ciphertext:   {recovered_message}")

    print("\n=============== RSA SIGNATURE ===============\n")
    print(f"Message:                {m_2}\n")

    m_2_signed = RSA_instance.sign(m_2, d_B, n_B)
    assert m_2_signed == 139946149260693867607112906574735868062749437621729152371217474062708529251204743665018991444038005832618912915250036414898959900238801293242485481120544999182886616669733899259575955678176133539745600054828147224713714471521374309679085794180533135483883902152178064817185104702608162450188184338147593819800, "Signature is not correct !"
    print(f"Signature:              {m_2_signed}\n")

    RSA_instance.check_signature(m_2, m_2_signed, e_B, n_B)

    print("\n\n============= STATION-TO-STATION ============\n")

    print(f"Alice to Bob\n")
    ax = RSA_instance.fast_exp(alpha, x, safe_prime)
    assert ax == 686072914171234798069517712764277594421530837248520761454562297567737629274501846654087857110320672185192257738624560988240804394506647168646502643636056310, "Secret a^x mod p not correct !"
    print(f"a^x mod p:  {ax}\n")

    print("Bob to Alice\n")
    ay = RSA_instance.fast_exp(alpha, y, safe_prime)
    K1 = RSA_instance.fast_exp(ax, y, safe_prime)
    assert ay == 1658758911043428653679670657159403893659858431555423238518923992311175752537434444470667284622227826513095646428663996761247179634768488071743521322105826864, "Secret a^y mod p not correct !"
    assert K1 == 133319045406894848338625909766918081728670119580456005459847062820377364927299550101232531204505214272971383981615061959224396184823089732799942062031596841, "Session key K is not correct !"
    SB_key = RSA_instance.sign(int(format(ax, '0b') + format(ay, '0b') + format(K1, '0b'), 2), d_B, n_B)
    assert SB_key == 63637939875901691094764242278906665544983903077054207988218710640087544761228273045150821483357729338737390290548046762350697337909101721771119707350314342587290126983794881205873189463125171775729781807366888186695684820979887485019292913876833243417638388536805972736525678021591270150561199609942649208004, "Signature from Bob on (alpha^x, alpha^y, K) is not correct !"
    print(f"a^y mod p:  {ay}\n")
    print(f"Signature:  {SB_key}\n")

    print(f"Alice to Bob\n")
    K2 = RSA_instance.fast_exp(ay, x, safe_prime)
    assert K2 == 133319045406894848338625909766918081728670119580456005459847062820377364927299550101232531204505214272971383981615061959224396184823089732799942062031596841, "Session key K is not correct !"
    RSA_instance.check_signature(int(format(ax, '0b') + format(ay, '0b') + format(K2, '0b'), 2), SB_key, e_B, n_B)
    print()
    SA_key = RSA_instance.sign(int(format(ay, '0b') + format(ax, '0b') + format(K2, '0b'), 2), d_A, n_A)
    assert SA_key == 45467152564432701103620506688535942942709188195272432989568457473601022575230584678514742692432145004914876272400870285574876815019240848540253393082439483176306291410816134069425004279929786767259112836051752427213131534826834152132670963428804617973787768260686245775875564276853832786703782164483812397373, "Signature from Alice on (alpha^y, alpha^x, K) is not correct !"
    print(f"Signature:  {SA_key}\n")

    print("Bob\n")
    RSA_instance.check_signature(int(format(ay, '0b') + format(ax, '0b') + format(K1, '0b'), 2), SA_key, e_A, n_A)
    print()

    print("\n---------------- Session key ----------------\n")
    print(K1)
    print("\n-------------------- END --------------------\n")





