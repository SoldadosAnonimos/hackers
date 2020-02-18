# enum identifiers are sourced from https://maecproject.github.io/documentation/maec5-docs/#introduction
from typing import Optional
from enum import Enum
import re

seen = [
    ('Alibaba', "Trojan:MacOS/eicar.com"),
    ('Alibaba', "Virus:Win32/Zatoxp.71d40539"),
    ('Alibaba', "Test:Any/EICAR.51848e83"),
    ('Alibaba', "Virus:Any/EICAR_Test_File.a4cca4b9"),
    ('Alibaba', "TrojanDropper:Android/Shedun.db57da0a"),
    ('Alibaba', "AdWare:Win32/BrowserIO.54759c87"),
    ('Alibaba', "RiskWare:Android/SMSreg.d8fc14c1"),
    ('Alibaba', "Trojan:Win32/Kryptik.45d18639"),
    ('Alibaba', "PUA:Win32/Softobase.50d4f335"),
    ('Alibaba', "RiskWare:Win32/NetPass.83e67f7c"),
    ('Alibaba', "virus:Win32/InfectPE.ali2000007"),
    ('Alibaba', "AdWare:Win32/BrowserIO.a429d2ee"),
    ('Alibaba', "RiskWare:Win32/Ammyy.1af2df39"),
    ('Alibaba', "Virus:Any/EICAR_Test_File.13208a8d"),
    ('Alibaba', "Ransom:Win32/CVE-2017-0147.716ea8c1"),
    ('Alibaba', "Ransom:Win32/CVE-2017-0147.f7a58ff4"),
    ('Alibaba', "Trojan:Win32/dark.ali1000040"),
    ('Alibaba', "TrojanDownloader:Win32/Agentb.d3d3cb66"),
    ('Alibaba', "Trojan:JS/Iframeinject.82fbaa39"),
    ('Alibaba', "Trojan:Win32/Kovter.8f1d0fa7"),
    ('Alibaba', "Backdoor:Win32/Meterpreter.99f8ed8f"),
    ('Alibaba', "Exploit:Win32/CVE-2020-0601.d7802b07"),
    ('Alibaba', "Virus:Any/EICAR_Test_File.b8db2e91"),
    ('ClamAV', "Win.Test.EICAR_HDB-1"),
    ('ClamAV', "Win.Virus.VMProtBad-6450060-0"),
    ('ClamAV', "Clamav.Test.File-7"),
    ('ClamAV', "Win.Packed.Sivis-6726654-0"),
    ('ClamAV', "Eicar-Test-Signature"),
    ('ClamAV', "Win.Trojan.SubSeven-38"),
    ('ClamAV', "Andr.Dropper.Smspay-6840229-0"),
    ('ClamAV', "Win.Trojan.Generic-6931301-0"),
    ('ClamAV', "Js.Malware.Autolike-1"),
    ('ClamAV', "Win.Trojan.Agent-36393"),
    ('ClamAV', "Js.Trojan.Obfus-633"),
    ('ClamAV', "Js.Coinminer.Generic-6836639-1"),
    ('ClamAV', "Html.Exploit.Agent-6598769-0"),
    ('ClamAV', "Legacy.Trojan.Agent-1388596"),
    ('ClamAV', "Andr.Malware.Paac-6888112-0"),
    ('ClamAV', "Js.Trojan.Redir-23"),
    ('ClamAV', "Win.Adware.Pswtool-104"),
    ('ClamAV', "Win.Virus.Parite-6748128-0"),
    ('ClamAV', "Win.Exploit.Countdown-1"),
    ('ClamAV', "Win.Ransomware.WannaCry-6313787-0"),
    ('ClamAV', "Win.Trojan.Kovter-6489152-1"),
    ('ClamAV', "Win.Trojan.MSShellcode-6360728-0"),
    ('ClamAV', "Win.Exploit.CVE_2020_0601-7542899-0"),

    # 'Concinnity', "Generic.Ransomware.btc.13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"),
    # 'CrowdStrike', "Falcon	win/malicious"),
    ('DrWeb', "Trojan.DownLoader32.61292"),
    ('DrWeb', "EICAR Test File (NOT a Virus!)"),
    ('DrWeb', "Win32.HLLW.Siggen.4657"),
    ('DrWeb', "BackDoor.Mbot.50"),
    ('DrWeb', "Android.Triada.120"),
    ('DrWeb', "JS.Click.243"),
    ('DrWeb', "JS.Facelike.10"),
    ('DrWeb', "HTML.BadLink.1"),
    ('DrWeb', "Trojan.Inor"),
    ('DrWeb', "JS.Packed.38"),
    ('DrWeb', "JS.HiddenLink.4"),
    ('DrWeb', "JS.Seospam.1"),
    ('DrWeb', "JS.Miner.11"),
    ('DrWeb', "JS.Redirector.based.2"),
    ('DrWeb', "JS.Click.370"),
    ('DrWeb', "JS.IFrame.700"),
    ('DrWeb', "VBS.Rmnet.5"),
    ('DrWeb', "JS.IFrame.777"),
    ('DrWeb', "Trojan.Vittalia.17937"),
    ('DrWeb', "JS.Redirector.206"),
    ('DrWeb', "Android.Backdoor.701.origin"),
    ('DrWeb', "JS.Redirector.112"),
    ('DrWeb', "JS.IFrame.805"),
    ('DrWeb', "JS.Click.345"),
    ('DrWeb', "JS.Redirector.304"),
    ('DrWeb', "JS.Redirector.386"),
    ('DrWeb', "JS.Redirector.396"),
    ('DrWeb', "JS.DownLoader.FakejQuery.1"),
    ('DrWeb', "JS.Click.334"),
    ('DrWeb', "JS.Click.348"),
    ('DrWeb', "Trojan.Encoder.11432"),
    ('DrWeb', "Trojan.DownLoader30.29180"),
    ('DrWeb', "JS.IFrame.680"),
    ('DrWeb', "Trojan.Starter.7434"),
    ('Ikarus', "Trojan-Banker.Emotet"),
    ('Ikarus', "EICAR-Test-File"),
    ('Ikarus', "Virus.Win32.Zatoxp"),
    ('Ikarus', "Backdoor.Win32.SubSeven"),
    ('Ikarus', "Trojan-Dropper.AndroidOS.Shedun"),
    ('Ikarus', "AdWare.Generic"),
    ('Ikarus', "Trojan.JS.Redirector"),
    ('Ikarus', "Trojan.JS.Clicker"),
    ('Ikarus', "Trojan-Clicker.JS.Faceliker"),
    ('Ikarus', "Trojan.JS.Framer"),
    ('Ikarus', "Trojan.Script"),
    ('Ikarus', "Packed.PUA.AndroidOS.Tencent"),
    ('Ikarus', "Virus.VBS.Ramnit"),
    ('Ikarus', "Trojan.JS.Script"),
    ('Ikarus', "Packed.PUA.AndroidOS.Qihoo"),
    ('Ikarus', "Trojan-SMS.AndroidOS.Agent"),
    ('Ikarus', "JS.Iframe"),
    ('Ikarus', "Trojan.JS.BlacoleRef"),
    ('Ikarus', "PUA.CoinMiner"),
    ('Ikarus', "Trojan.JS.HiddenLink"),
    ('Ikarus', "JS.Faceliker"),
    ('Ikarus', "Trojan.JS.TrojanClicker"),
    ('Ikarus', "Trojan.Iframer"),
    ('Ikarus', "Virus.JS.Obfuscator"),
    ('Ikarus', "Trojan.JS.IFrame"),
    ('Ikarus', "PUA.Toolbar.Conduit"),
    ('Ikarus', "Trojan.JS.Iframeinject"),
    ('Ikarus', "PUA.Win32.Prepscram"),
    ('Ikarus', "HTML.ExploitKit"),
    ('Ikarus', "Trojan.AndroidOS.Agent"),
    ('Ikarus', "HEUR.Trojan.Script"),
    ('Ikarus', "PUA.AndroidOS.Jiagu"),
    ('Ikarus', "Trojan-Downloader.JS.Fakejquery"),
    ('Ikarus', "JS.Redir"),
    ('Ikarus', "Trojan.AndroidOS.Jiagu"),
    ('Ikarus', "Trojan.JS.Crypt"),
    ('Ikarus', "PUA.AndroidOS.Secapk"),
    ('Ikarus', "Trojan.Script.Injector"),
    ('Ikarus', "Riskware.Win32.RemoteAdmin"),
    ('Ikarus', "Exploit.HTML.IframeBof"),
    ('Ikarus', "Exploit.CVE-2017-0147"),
    ('Ikarus', "Trojan-Ransom.WannaCry"),
    ('Ikarus', "Trojan-Downloader.Win32.Agent"),
    ('Ikarus', "Trojan-Downloader.JS.Iframe"),
    ('Ikarus', "PUA.RiskWare.PEMalform"),
    ('Ikarus', "Trojan.Win32.Rozena"),
    ('Jiangmin', "EICAR-Test-File"),
    ('Jiangmin', "Win32/Lamer.l"),
    ('Jiangmin', "Backdoor/Agent.abep"),
    ('Jiangmin', "AdWare.Gertokr.h"),
    ('Jiangmin', "Trojan/Script.Gen"),
    ('Jiangmin', "Trojan.Script.nbd"),
    ('Jiangmin', "Trojan.JS.aqg"),
    ('Jiangmin', "Trojan.Script.Generic1"),
    ('Jiangmin', "TrojanDownloader.JS.arto"),
    ('Jiangmin', "1878"),
    ('Jiangmin', "KVBASE"),
    ('Jiangmin', "AdWare.Gertokr.i"),
    ('Jiangmin', "TrojanDownloader.JS.oa"),
    ('Jiangmin', "AdWare.StartSurf.szo"),
    ('Jiangmin', "Trojan.Script.gkb"),
    ('Jiangmin', "Adware.Agent.aljy"),
    ('Jiangmin', "TrojanDownloader.JS.awlu"),
    ('Jiangmin', "Trojan.Script.poc"),
    ('Jiangmin', "PSWTool.NetPass.cw"),
    ('Jiangmin', "RemoteAdmin.Ammyy.c"),
    ('Jiangmin', "Trojan.Hesv.dnb"),
    ('Jiangmin', "Exploit.Script.ms"),
    ('Jiangmin', "Trojan.Wanna.k"),
    ('Jiangmin', "Trojan.WanaCry.i"),
    ('Jiangmin', "Trojan.Agentb.fpo"),
    ('Jiangmin', "Trojan.Generic.eiawf"),
    ('Jiangmin', "Exploit.Multi.y"),
    ('K7', "EICAR_Test_File"),
    ('K7', "Virus ( 004d554e1 )"),
    ('K7', "Backdoor ( 000032d31 )"),
    ('K7', "Trojan ( 00536a311 )"),
    ('K7', "Exploit ( 04c5519d1 )"),
    ('K7', "Trojan ( 00531bae1 )"),
    ('K7', "Exploit ( 04c554ce1 )"),
    ('K7', "Trojan ( 0053576b1 )"),
    ('K7', "Trojan ( 0001140e1 )"),
    ('K7', "Trojan ( 005071571 )"),
    ('K7', "Trojan ( 0053d3381 )"),
    ('K7', "Exploit ( 04c559b91 )"),
    ('K7', "Riskware ( 0040eff71 )"),
    ('K7', "Trojan ( 00545d801 )"),
    ('K7', "Trojan ( 0054e95b1 )"),
    ('K7', "Exploit ( 04c55c991 )"),
    ('K7', "Unwanted-Program ( 004d672e1 )"),
    ('K7', "Trojan ( 005259891 )"),
    ('K7', "Unwanted-Program ( 004d38111 )"),
    ('K7', "Trojan ( 000139291 )"),
    ('K7', "Trojan ( 00557fc41 )"),
    ('K7', "Exploit ( 0050d7a31 )"),
    ('K7', "Trojan-Downloader ( 005593801 )"),
    ('K7', "Trojan ( 004f5da31 )"),
    ('K7', "Trojan ( 00116c681 )"),
    ('Lionic', "Test.File.EICAR.y!c"),
    ('Lionic', "Virus.Win32.Lamer.n!c"),
    ('Lionic', "Trojan.HTML.Generic.4!c"),
    ('Lionic', "SUSPICIOUS"),
    ('Lionic', "Trojan.Win32.Generic.4!c"),
    ('Lionic', "Trojan.Win32.Wanna.!c"),
    ('Lionic', "Trojan.Win32.Ursu.4!c"),
    ('Lionic', "Trojan.Win32.Generic.m!c"),
    ('Lionic', "Hacktool.Multi.CVE-2020-0601.3!c"),
    ('Lionic', "Trojan.Win32.Wanna.u!c"),
    ('Lionic', "Trojan.PowerShell.Agent.4!c"),
    ('NanoAV', "Marker.Dos.EICAR-Test-File.dyb"),
    ('NanoAV', "Trojan.Android.MLW.ebzlbe"),
    ('NanoAV', "Trojan.Script.Redir.cskpac"),
    ('NanoAV', "Trojan.Script.Click.ecobpj"),
    ('NanoAV', "Trojan.Script.Facelike.ehdabi"),
    ('NanoAV', "Trojan.Html.Iframe.dcipov"),
    ('NanoAV', "Trojan.Url.IframeB.laqfz"),
    ('NanoAV', "Trojan.Html.Agent.dxibai"),
    ('NanoAV', "Trojan.Script.Agent.ezsjwb"),
    ('NanoAV', "Riskware.Android.SMSSend.bqbevx"),
    ('NanoAV', "Trojan.Script.Agent.dozdte"),
    ('NanoAV', "Trojan.Script.Agent.duujlm"),
    ('NanoAV', "Riskware.Script.Miner.fmbqgs"),
    ('NanoAV', "Trojan.Script.ExpKit.erfceu"),
    ('NanoAV', "Trojan.Script.Redirector.yrnhc"),
    ('NanoAV', "Trojan.Script.AgentClick.dchycs"),
    ('NanoAV', "Trojan.Script.IframeDQ.czzusk"),
    ('NanoAV', "Trojan.Nsis.Adload.fjtptt"),
    ('NanoAV', "Trojan.Script.Iframe.zqwnd"),
    ('NanoAV', "Trojan.Html.Iframe.dczskt"),
    ('NanoAV', "Virus.Win32.Lamer.zocpe"),
    ('NanoAV', "Riskware.Win32.RemoteAdmin.csowxz"),
    ('NanoAV', "Trojan.Script.Autorun.dqzzbx"),
    ('NanoAV', "Trojan.Html.hidIFrame.ejgwvr"),
    ('NanoAV', "Trojan.Script.FaceLiker.fdpzpz"),
    ('NanoAV', "Trojan.Win32.Wanna.epxkni"),
    ('NanoAV', "Trojan.Win32.Wanna.eovgam"),
    ('NanoAV', "Trojan.Win32.Dwn.gelidv"),
    ('NanoAV', "Riskware.Win32.StartSurf.fksxkj"),
    ('NanoAV', "Trojan.Script.Iframe.dzfjls"),
    ('NanoAV', "Trojan.Win32.Malformed.evafmt"),
    ('NanoAV', "Trojan.Win32.Swrort.eratya"),
    ('NanoAV', "Trojan.Win32.Wanna.epclsl"),
    ('NanoAV', "Riskware.Android.Leadbolt.dkzuxh"),
    ('Qihoo360', "qex.eicar.gen.gen"),
    ('Qihoo360', "Win32/Virus.FileInfector.A"),
    ('Qihoo360', "Malware.Radar01.Gen"),
    ('Qihoo360', "Trojan.Android.Gen"),
    ('Qihoo360', "Win32/Virus.Adware.f5d"),
    ('Qihoo360', "virus.html.gen03.30"),
    ('Qihoo360', "html.script.facelike.b"),
    ('Qihoo360', "virus.html.gen03.346"),
    ('Qihoo360', "Generic/Trojan.2dc"),
    ('Qihoo360', "virus.url.script.a"),
    ('Qihoo360', "virus.vbs.writebin.a"),
    ('Qihoo360', "trojan.html.redirector.b"),
    ('Qihoo360', "Win32/Trojan.Ransom.ed7"),
    ('Qihoo360', "virus.html.gen03.26"),
    ('Qihoo360', "virus.html.gen03.17"),
    ('Qihoo360', "trojan-clicker.js.agent.ma"),
    ('Qihoo360', "virus.js.qexvmc.1"),
    ('Qihoo360', "html.script.facelike.a"),
    ('Qihoo360', "virus.html.gen03.131"),
    ('Qihoo360', "js.iframe.adware.a"),
    ('Qihoo360', "Win32/Virus.Adware.059"),
    ('Qihoo360', "virus.html.gen03.595"),
    ('Qihoo360', "virus.html.gen03.272"),
    ('Qihoo360', "virus.html.gen03.417"),
    ('Qihoo360', "trojan.js.likejack.a"),
    ('Qihoo360', "Win32/Virus.PSW.f65"),
    ('Qihoo360', "Win32/Application.RemoteAdmin.1b9"),
    ('Qihoo360', "virus.html.gen03.1142"),
    ('Qihoo360', "virus.html.gen03.16"),
    ('Qihoo360', "Win32/Worm.WannaCrypt.W"),
    ('Qihoo360', "Win32/Trojan.Ransom.62c"),
    ('Qihoo360', "HEUR/QVM20.1.49AD.Malware.Gen"),
    ('Qihoo360', "Win32/Trojan.87c"),
    ('Qihoo360', "Win32/Backdoor.d55"),
    ('Qihoo360', "Trojan.Generic"),
    ('Qihoo360', "Win32/Worm.WannaCrypt.B"),
    ('QuickHeal', "EICAR.TestFile"),
    ('QuickHeal', "Trojan.Agent"),
    ('QuickHeal', "Backdoor.Subseven"),
    ('QuickHeal', "Android.Shedun.E"),
    ('QuickHeal', "Trojan.MauvaiseRI.S5263730"),
    ('QuickHeal', "HTML/Redirector.NG"),
    ('QuickHeal', "JS/Faceliker.CN"),
    ('QuickHeal', "JS/Faceliker.D"),
    ('QuickHeal', "JS.Redirector.AN"),
    ('QuickHeal', "JS/Iframe.AE"),
    ('QuickHeal', "VBS.Dropper.A"),
    ('QuickHeal', "Android.RuSMS.A"),
    ('QuickHeal', "Trojan.Hidelink.A"),
    ('QuickHeal', "Coinhive.Miner.30698"),
    ('QuickHeal', "JS.Agent.S"),
    ('QuickHeal', "JS.Redirector.AB"),
    ('QuickHeal', "JS.Faceliker.NC"),
    ('QuickHeal', "HTML.Agent.EC"),
    ('QuickHeal', "JS.Nemucod.TU"),
    ('QuickHeal', "JS.Nemucod.ADX"),
    ('QuickHeal', "JS.FakejQuery.A"),
    ('QuickHeal', "Trojan.GenericPMF.S3026899"),
    ('QuickHeal', "Trojan.Generic"),
    ('QuickHeal', "Exp.HTML.CVE-2008-2551.C"),
    ('QuickHeal', "ansom.WannaCrypt.S1670344"),
    ('QuickHeal', "Ransomware.WannaCry.IRG1"),
    ('QuickHeal', "Swbndlr.Dlhelper.V4"),
    ('QuickHeal', "JS.Iframe.O"),
    ('QuickHeal', "Trojan.Kovter.S5621"),
    ('Rising', "Trojan.Kryptik!8.8"),
    ('Rising', "Virus.EICAR_Test_File!8.D9E"),
    ('Rising', "Virus.Lamer!1.A4FA"),
    ('Rising', "Trojan.Sub7.22.a"),
    ('Rising', "Virus.Undefined!8.23"),
    ('Rising', "Trojan.ScrInject!8.A"),
    ('Rising', "Dropper.Shedun/Android!8.3F4"),
    ('Rising', "Hoax.Uniblue!8.100E9"),
    ('Rising', "PUA.Conduit!8.122"),
    ('Rising', "Trojan.Kryptik!1.B4F7"),
    ('Rising', "Trojan.Redirector!8.E"),
    ('Rising', "Trojan.Agent/Android!8.358"),
    ('Rising', "PUA.Softobase!8.654"),
    ('Rising', "Trojan.Clicker-Faceliker!8.37F"),
    ('Rising', "Trojan.Vigorf!8.EAEA"),
    ('Rising', "Trojan.Bitrep!8.F596"),
    ('Rising', "PUA.Presenoker!8.F608"),
    ('Rising', "Ransom.WanaCrypt!1.AAED"),
    ('Rising', "Ransom.Wanna!8.E7B2"),
    ('Rising', "Downloader.Agent!8.B23"),
    ('Rising', "Trojan.Iframeinject!8.3C8"),
    ('Rising', "Trojan.Generic!8.C3"),
    ('Rising', "Trojan.Meterpreter!1.AEA1"),
    ('Rising', "Exploit.CVE-2020-0601!8.1168A"),
    ('Rising', "Trojan.Agent!8.B1E"),

    # gov.br; mil.br; leg.br; jus.br
    # ('TACHYON', "EICAR-Test-File"),
    # ('URLHaus', "EICAR File"),
    ('Virusdie', "EICAR.TEST"),
    ('Virusdie', "Doc.write.unescape"),
    ('Virusdie', "InjectHEX.HTML"),
    ('Virusdie', "Iframe.dnnViewState"),
    ('Virusdie', "JS.Inject.45"),
    ('Virusdie', "Miner.Coinhive.Include"),
    ('Virusdie', "JS.Inject.80"),
    ('Virusdie', "Trojan.WSHshell"),
    ('Virusdie', "Trojan.Inject.7"),
    ('Virusdie', "JS.Inject.12"),
    ('Virusdie', "JS.Inject.34"),
    ('Virusdie', "Trojan.Inject.26"),

    # ('XVirus', "Suspicious:NewThreat.179"),
    # ('XVirus', "Suspicious:NewThreat.101"),
    # ('XVirus', "Suspicious:NewThreat.263"),
]


class MalwareLabel(Enum):
    ADWARE = 'adware'
    APPENDER = 'appender'
    BACKDOOR = 'backdoor'
    BOOTSECTORVIRUS = 'boot sector virus'
    BOT = 'bot'
    CLICKER = 'clicker'
    DOWNLOADER = 'downloader'
    TROJANCLICKER = CLICKER
    TROJANDOWNLOADER = DOWNLOADER
    JS = 'js'
    DROPPER = 'dropper'
    TROJANDROPPER = DROPPER
    FORKBOMB = 'fork bomb'
    GREYWARE = 'greyware'
    UNWANTED_PROGRAM = GREYWARE
    RISKWARE = GREYWARE
    PUA = GREYWARE
    TEST = 'test'
    EICAR = TEST
    HACKTOOL = GREYWARE
    IMPLANT = 'implant'
    INFECTOR = 'infector'
    KEYLOGGER = 'keylogger'
    KLEPTOGRAPHICWORM = 'kleptographic worm'
    MACROVIRUS = 'macro virus'
    MALCODE = 'malcode'
    MASSMAILER = 'mass-mailer'
    PASSWORDSTEALER = 'password stealer'
    PREPENDER = 'prepender'
    RANSOMWARE = 'ransomware'
    RANSOM = RANSOMWARE
    RAT = 'rat'
    ROOTKIT = 'rootkit'
    SHELLCODE = 'shellcode'
    EXPLOIT = SHELLCODE
    SPYWARE = 'spyware'
    TROJANHORSE = 'trojan horse'
    TROJAN = TROJANHORSE
    TROJANBANKER = TROJAN
    TROJANSMS = TROJAN
    VIRUS = 'virus'
    WABBIT = 'wabbit'
    WEBBUG = 'web bug'
    WIPER = 'wiper'
    WORM = 'worm'
    ZIPBOMB = 'zip bomb'

    @classmethod
    def construct(cls, **values):
        try:
            label = (values.get('label') or '').upper().replace('-', ' ').replace(' ', '')
            return getattr(cls, label) or cls(label)
        except (AttributeError, ValueError):
            return None


class OperatingSystem(Enum):
    GENERIC = 'generic'
    ANY = GENERIC
    WEB = 'html'
    WINDOWS = 'windows'
    TEST = 'test'
    EICAR = TEST
    JS = WEB
    SCRIPT = JS
    HTML = WEB
    WIN = WINDOWS
    WIN32 = WINDOWS
    WIN64 = WINDOWS
    LEGACY = GENERIC
    LINUX = 'linux'
    OSX = 'mac-os-x'
    MACOS = OSX
    ANDROID = 'android'
    ANDR = ANDROID
    VBS = WINDOWS
    IOS = 'ios'

    @classmethod
    def construct(cls, **values):
        try:
            platform = (values.get('platform') or '').upper()
            return getattr(cls, platform) or cls(platform)
        except (AttributeError, ValueError):
            return None


class ProcessorArchitecture(Enum):
    X86 = 'x86'
    X64 = 'x86-64'
    ARM = 'arm'
    MIPS = 'mips'

    WIN32 = X86
    WIN64 = X64

    @classmethod
    def construct(cls, **values):
        try:
            platform = (values.get('platform') or '').upper()
            return getattr(cls, platform, cls(platform))
        except ValueError:
            return None


class ObfuscationMethod(Enum):
    PACKER = 'packer'

    @classmethod
    def construct(cls, **values):
        if 'packed' in values.get('label', {}) or 'packed' in values.get('platform', {}):
            return ObfuscationMethod.PACKER
        return None


class MalwareFamily:
    name: Optional[str]
    variant_id: Optional[str]
    operating_system: Optional[OperatingSystem]
    architecture: Optional[ProcessorArchitecture]
    label: Optional[MalwareLabel]
    obfuscation_method: Optional[ObfuscationMethod]

    def __init__(self, **values):
        values = {k: v for k, v in values.items() if v}
        self.name = values.get('name')
        self.variant_id = values.get('variant_id')
        self.operating_system = OperatingSystem.construct(**values)
        self.architecture = ProcessorArchitecture.construct(**values)
        self.label = MalwareLabel.construct(**values)
        self.obfuscation_method = ObfuscationMethod.construct(**values)

    def __repr__(self):
        return f'MalwareFamily(name={self.name}, label={self.label}, os={self.operating_system}, arch={self.architecture})'


class Engine:
    regex: str

    def __init__(self, regex):
        self.regex = regex

    def parse(self, family: str):
        m = re.match(self.regex, family)
        if m:
            return MalwareFamily(**m.groupdict())
        else:
            print("%s didn't match the regex for %s" % (family, self.regex))


class FamilyExtractor:
    alibaba = Engine(r"^((?P<label>\w+):)?((?P<platform>\w+)\/)?((?P<name>[^.]+))(\.(?P<vendor_id>.*))?$")
    clamav: Engine = Engine(
        r"((?P<platform>\w+)\.)?((?P<label>\w+)\.)?(?P<name>\w+)?(-?P<vendor_id>[0-9]*)?")
    drweb: Engine = Engine(r"((?P<platform>\w+)\.)?((?P<label>\w+)\.)?(?P<name>\w+)\.(?P<vendor_id>.*)")
    ikarus: Engine = Engine(r"((?P<obfuscation>Packed).)?((?P<label>[-\w]+)\.)?((?P<platform>\w+)\.)?((?P<name>[\w-]+))(\.?(?P<vendor_id>.*))?")
    jiangmin: Engine = Engine(r"((?P<platform>\w+)?\/)?((?P<label>\w+)\.)?((?P<name>\w+)\.)?(?P<extra>\w*)")
    k7: Engine = Engine(r"(?P<label>[\w-]+)( \( (?P<vendor_id>[a-f0-9]+) \))?")
    lionic: Engine = Engine(r"((?P<label>\w+)\.)?((?P<platform>\w+)\.)?((?P<name>\w*))(\!\w.*)?")
    nanoav: Engine = Engine(r"((?P<label>\w*)\+)?((?P<platform>\w+)\.)?(?P<name>[^.]*)\.(\w.*)")
    qihoo360: Engine = Engine(r"^((?P<platform>\w+)\/)?((?P<label>[^.]+)\.)((?P<name>\w+)\.)?(.*)$")
    quickheal: Engine = Engine(r"((?P<platform>\w+)\/)?((?P<label>\w+)\.)?(?P<name>\w+)\.(\w.*)")
    rising: Engine = Engine(r"((?P<label>\w+)\.)?((?P<name>\w+))?(\!(P<extra>.*))?")
    virusdie: Engine = Engine(r"((?P<label>\w+)\.)?((?P<behavior>\w+)\.)?(?P<extra>\w*)")

    @classmethod
    def parse(cls, engine, family: str) -> MalwareFamily:
        extractor = getattr(cls, engine.lower())
        return extractor.parse(family)


if __name__ == '__main__':
    for engine, family in seen:
        print(FamilyExtractor.parse(engine, family))
        
     
