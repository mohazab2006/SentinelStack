import Image from "next/image";

export default function SiteLogo() {
  return (
    <div className="site-logo-mark">
      <Image
        src="/logo.png"
        alt=""
        width={220}
        height={80}
        className="site-logo-img"
        priority
        sizes="(max-width: 640px) min(160px, 38vw) 200px"
      />
    </div>
  );
}
