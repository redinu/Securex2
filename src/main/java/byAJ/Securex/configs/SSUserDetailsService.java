package byAJ.Securex.configs;

import java.util.HashSet;
import java.util.Set;

import javax.transaction.Transactional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import byAJ.Securex.models.Role;
import byAJ.Securex.models.User;
import byAJ.Securex.repositories.UserRepository;

@Transactional
public class SSUserDetailsService implements UserDetailsService{
	
	private UserRepository userRepository;
	
	public SSUserDetailsService(UserRepository userRepository){
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User user= userRepository.findByUsername(username);
		if(user==null){
			return null;
		} else{
			return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),getAuthorities(user));
		}
	}
	
	public Set<GrantedAuthority> getAuthorities(User user){
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
		for(Role role : user.getRoles()){
			GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(role.getRole());
			authorities.add(grantedAuthority);
		}
		
		return authorities;
	}
}
