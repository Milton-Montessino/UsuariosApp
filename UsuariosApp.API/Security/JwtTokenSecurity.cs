using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace UsuariosApp.API.Security
{
    /// <summary>
    /// Classe utilizada para a geração dos Tokens
    /// </summary>
    public class JwtTokenSecurity
    {
        #region Propriedades

        /// <summary>
        /// Chave secreta para assinatura dos TOKENS (chave antifalsificação)
        /// </summary>
        public static string SecurityKey => "C341760A-F118-4CCF-93BF-7DCD5D5B5906";

        /// <summary>
        /// Tempo de expiração do TOKEN em horas
        /// </summary>
        public static int ExpirationInHours => 1;

        #endregion

        /// <summary>
        /// Método para gerar os TOKENS JWT do projeto
        /// </summary>
        public static string GenerateToken(Guid userId)
        {
            //convertendo a chave secreta para formato bytes
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(SecurityKey);

            //criar o conteúdo do TOKEN JWT
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //adicionar o ID do usuário (Identificação do usuário)
                Subject = new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Name, userId.ToString()) }),

                //definindo a data e hora de expiração do TOKEN
                Expires = DateTime.UtcNow.AddHours(ExpirationInHours),

                //adicionar a chave secreta antifalsificação do TOKEN
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            //retornando o TOKEN
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

    }
}
